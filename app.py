import sqlite3
import jwt
from flask import Flask, jsonify, request
from flask_cors import CORS
from datetime import datetime, timedelta, timezone
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

# ==================================
# App & DB 초기화
# ==================================
app = Flask(__name__)

#softwareengineering SHA256 Hashing
app.config['SECRET_KEY'] = 'dd7806c6d3a20b248454a0565951c0fd8212277c34e0439d758b85ff3a3b9e77'

CORS(app, resources={r"/api/*": {"origins": "http://localhost:5173"}}, supports_credentials=True)


@app.before_request
def log_request_info():
    app.logger.debug('Request Headers: %s', request.headers)
    app.logger.debug('Request Method: %s', request.method)
    app.logger.debug('Request Path: %s', request.path)


DB_PATH = 'restaurant.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS Users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS DiningTables (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            location TEXT NOT NULL,
            capacity INTEGER NOT NULL,
            UNIQUE(location, capacity)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS Reservations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            table_id INTEGER NOT NULL,
            reservation_date TEXT NOT NULL,
            time_slot TEXT NOT NULL,
            guest_name TEXT NOT NULL,
            guest_phone TEXT NOT NULL,
            guest_credit_card TEXT NOT NULL,
            number_of_guests INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES Users(id),
            FOREIGN KEY(table_id) REFERENCES DiningTables(id)
        )
    ''')
    try:
        dining_tables = [
            ('창가자리', 2), ('창가자리', 4), ('창가자리', 6),
            ('안쪽자리', 2), ('안쪽자리', 4), ('안쪽자리', 6),
            ('룸석', 4), ('룸석', 6), ('룸석', 8)
        ]
        c.executemany('INSERT INTO DiningTables (location, capacity) VALUES (?, ?)', dining_tables)
    except sqlite3.IntegrityError:
        pass
    conn.commit()
    conn.close()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        
        if not token:
            return jsonify({'message': '토큰이 존재하지 않습니다.'}), 401
        
        try:
            
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("SELECT id, email, username FROM Users WHERE id = ?", (data['user_id'],))
            current_user_row = c.fetchone()
            conn.close()
            if not current_user_row:
                 return jsonify({'message': '유효하지 않은 토큰입니다.'}), 401
            current_user = {"id": current_user_row[0], "email": current_user_row[1], "username": current_user_row[2]}
        except jwt.ExpiredSignatureError:
            return jsonify({'message': '토큰이 만료되었습니다.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': '유효하지 않은 토큰입니다.'}), 401
        
        # 데코레이터가 적용된 함수에 현재 사용자 정보를 전달
        return f(current_user, *args, **kwargs)
    return decorated

# ==================================
# API Routes
# ==================================

# --- 인증 APIs ---
@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json()
    email = data.get('email')
    username = data.get('username')
    password = data.get('password')

    if not all([email, username, password]):
        return jsonify({"success": False, "message": "모든 필드를 입력해주세요."}), 400

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO Users (email, username, password) VALUES (?, ?, ?)", (email, username, hashed_password))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "회원가입 성공!"})
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "이미 존재하는 이메일입니다."}), 409

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, email, username, password FROM Users WHERE email = ?", (email,))
    user_row = c.fetchone()
    conn.close()

    if user_row and check_password_hash(user_row[3], password):
        token = jwt.encode({
            'user_id': user_row[0],
            'exp': datetime.now(timezone.utc) + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        user_data = {"id": user_row[0], "email": user_row[1], "username": user_row[2]}
        return jsonify({"success": True, "message": "로그인 성공!", "token": token, "user": user_data})
    else:
        return jsonify({"success": False, "message": "이메일 또는 비밀번호가 올바르지 않습니다."}), 401

@app.route("/api/logout", methods=["POST"])
@token_required
def logout(current_user):
    return jsonify({"success": True, "message": f"{current_user['username']}님, 성공적으로 로그아웃되었습니다."})


# --- 테이블 APIs ---
@app.route("/api/tables/available", methods=["GET"])
@token_required
def get_available_tables(current_user):
    date = request.args.get('date')
    time_slot = request.args.get('time')
    
    if not date or not time_slot:
        return jsonify({"error": "날짜와 시간대를 모두 지정해야 합니다."}), 400

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT table_id FROM Reservations WHERE reservation_date = ? AND time_slot = ?', (date, time_slot))
    booked_table_ids = [row[0] for row in c.fetchall()]

    if booked_table_ids:
        placeholders = ','.join('?' for _ in booked_table_ids)
        query = f"SELECT id, location, capacity FROM DiningTables WHERE id NOT IN ({placeholders})"
        c.execute(query, booked_table_ids)
    else:
        c.execute("SELECT id, location, capacity FROM DiningTables")

    available_tables = [{"id": row[0], "location": row[1], "capacity": row[2]} for row in c.fetchall()]
    conn.close()
    
    return jsonify(available_tables)

# --- 예약 APIs ---
@app.route("/api/reservations", methods=["POST"])
@token_required
def make_reservation(current_user):
    data = request.get_json()
    
    user_id = current_user['id'] 

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id FROM DiningTables WHERE location = ? AND capacity = ?", (data['location'], data['capacity']))
    table_row = c.fetchone()
    if not table_row:
        conn.close()
        return jsonify({"success": False, "message": "존재하지 않는 테이블입니다."}), 404
    table_id = table_row[0]

    c.execute('''
        INSERT INTO Reservations (user_id, table_id, reservation_date, time_slot, guest_name, guest_phone, guest_credit_card, number_of_guests)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (user_id, table_id, data['date'], data['time'], data['name'], data['phone'], data['cardNumber'], data['peopleCount']))
    
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "message": "예약이 성공적으로 완료되었습니다."})


@app.route("/api/my-reservations", methods=["GET"])
@token_required
def get_my_reservations(current_user):
    user_id = current_user['id'] 

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        SELECT r.id, r.reservation_date, r.time_slot, t.location, t.capacity, r.guest_name, r.guest_phone, r.number_of_guests
        FROM Reservations r JOIN DiningTables t ON r.table_id = t.id
        WHERE r.user_id = ? ORDER BY r.reservation_date DESC
    ''', (user_id,))
    
    reservations = [{"id": row[0], "date": row[1], "time": row[2], "location": row[3], "capacity": row[4],
                     "name": row[5], "phone": row[6], "peopleCount": row[7]} for row in c.fetchall()]
    conn.close()
    return jsonify(reservations)

@app.route("/api/reservations/<int:reservation_id>", methods=["DELETE"])
@token_required
def cancel_reservation(current_user, reservation_id):
    user_id_from_token = current_user['id']

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("SELECT user_id, reservation_date FROM Reservations WHERE id = ?", (reservation_id,))
    res_row = c.fetchone()
    
    if not res_row:
        conn.close()
        return jsonify({"success": False, "message": "존재하지 않는 예약입니다."}), 404
        
    owner_id, res_date_str = res_row
    
    
    if user_id_from_token != owner_id:
        conn.close()
        return jsonify({"success": False, "message": "예약을 취소할 권한이 없습니다."}), 403

    res_date = datetime.strptime(res_date_str, '%Y-%m-%d').date()
    if (res_date - datetime.now().date()).days < 1:
        conn.close()
        return jsonify({"success": False, "message": "예약 당일 또는 지난 예약은 취소할 수 없습니다."}), 400
        
    c.execute("DELETE FROM Reservations WHERE id = ?", (reservation_id,))
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "message": "예약이 취소되었습니다."})

if __name__ == "__main__":
    init_db()
    app.run(port=5001, debug=True)