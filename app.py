from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta
import random
import smtplib
from email.mime.text import MIMEText
from config import MONGO_URI, DB_NAME, JWT_SECRET_KEY, SECRET_KEY, SENDER_EMAIL, SENDER_PASSWORD
from flask_cors import CORS
from bson.objectid import ObjectId
import cloudinary.uploader
import cloudinary
from config import cloudinary_config  
import base64
from io import BytesIO
from google.oauth2 import id_token
from google.auth.transport import requests


app = Flask(__name__)
CORS(app)

# Konfigurasi MongoDB
app.config["MONGO_URI"] = f"{MONGO_URI}/{DB_NAME}"
app.config['SECRET_KEY'] = SECRET_KEY
app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY

cloudinary.config(
    cloud_name=cloudinary_config['cloud_name'],
    api_key=cloudinary_config['api_key'],
    api_secret=cloudinary_config['api_secret']
)


mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def send_otp_email(receiver_email, otp_code):
    msg = MIMEMultipart("alternative")
    msg['Subject'] = 'Kode OTP Anda'
    msg['From'] = SENDER_EMAIL
    msg['To'] = receiver_email

    otp_html_template = f"""
<html>
  <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0;">
    <div style="max-width: 600px; margin: 30px auto; background-color: #ffffff; padding: 30px; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.05);">
      <div style="text-align: center;">
        <img src="https://res.cloudinary.com/dmxxdry19/image/upload/c_crop,w_400,h_400,g_auto/v1748281045/onboard_m8sirj.jpg" 
             alt="image" 
             width="200" 
             style="margin-bottom: 20px; border-radius: 8px;" />
        <h2 style="color: #2E7D32; margin-bottom: 10px;">Verifikasi Kode OTP Anda</h2>
        <p style="font-size: 16px; color: #555;">Halo,</p>
        <p style="font-size: 16px; color: #555;">
          Terima kasih telah mendaftar di <strong>SwingPRO</strong>.<br/>
          Gunakan kode OTP di bawah ini untuk menyelesaikan proses verifikasi akun Anda:
        </p>
        <div style="margin: 30px 0;">
          <span style="display: inline-block; background-color: #2E7D32; color: #ffffff; padding: 15px 30px; font-size: 26px; font-weight: bold; letter-spacing: 4px; border-radius: 6px;">
            {otp_code}
          </span>
        </div>
        <p style="font-size: 14px; color: #888;">
          Kode ini berlaku selama <strong>1 menit</strong>. Jangan bagikan kode ini kepada siapa pun.
        </p>
        <p style="font-size: 14px; color: #888;">
          Jika Anda tidak meminta kode ini, Anda dapat mengabaikan email ini.
        </p>
        <br/>
        <p style="font-size: 16px; color: #333;">Salam hangat,</p>
        <p style="font-size: 16px; color: #2E7D32; font-weight: bold;">SwingPRO</p>
      </div>
    </div>
  </body>
</html>
"""


    mime_html = MIMEText(otp_html_template, 'html')
    msg.attach(mime_html)

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, receiver_email, msg.as_string())
        server.quit()
        print(f"OTP sent to {receiver_email}")
    except Exception as e:
        print(f"Failed to send OTP email: {e}")
        raise e


def generate_otp():
    return str(random.randint(100000, 999999))

def otp_expiration_time(minutes=1):
    return datetime.utcnow() + timedelta(minutes=minutes)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400

    existing_user = mongo.db.users.find_one({'email': email})
    if existing_user:
        return jsonify({'message': 'User already exists'}), 409

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    otp_code = generate_otp()
    expires_at = otp_expiration_time(minutes=5)

    new_user = {
        'username': username,
        'email': email,
        'password': hashed_password,
        'otp': otp_code,
        'otp_verified': False,
        'otp_expires_at': expires_at,
        'created_at': datetime.utcnow()
    }

    mongo.db.users.insert_one(new_user)

    try:
        send_otp_email(email, otp_code)
    except Exception as e:
        mongo.db.users.delete_one({'email': email})
        return jsonify({'message': 'Failed to send OTP email'}), 500

    return jsonify({'message': 'User registered successfully. Please check your email for the OTP.'}), 201

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    otp_input = data.get('otp')

    if not otp_input:
        return jsonify({'message': 'OTP is required'}), 400

    user = mongo.db.users.find_one({'otp': otp_input, 'otp_verified': False})
    if not user:
        return jsonify({'message': 'Invalid OTP'}), 400

    now = datetime.utcnow()
    if 'otp_expires_at' in user and now > user['otp_expires_at']:
        new_otp = generate_otp()
        new_expiry = otp_expiration_time()

        mongo.db.users.update_one(
            {'_id': user['_id']},
            {'$set': {'otp': new_otp, 'otp_expires_at': new_expiry}}
        )

        try:
            send_otp_email(user['email'], new_otp)
        except Exception as e:
            return jsonify({'message': 'OTP expired and failed to resend new OTP'}), 500

        return jsonify({'message': 'OTP expired. A new OTP has been sent to your email.'}), 400

    mongo.db.users.update_one(
        {'_id': user['_id']},
        {'$set': {'otp_verified': True}, '$unset': {'otp': '', 'otp_expires_at': ''}}
    )
    return jsonify({'message': 'OTP verified successfully', 'email': user['email']}), 200


# Tambahkan endpoint resend-otp manual jika ingin
@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({'message': 'Email is required'}), 400

    user = mongo.db.users.find_one({'email': email})
    if not user:
        return jsonify({'message': 'User not found'}), 404

    if user.get('otp_verified'):
        return jsonify({'message': 'OTP already verified'}), 400

    new_otp = generate_otp()
    new_expiry = otp_expiration_time()

    mongo.db.users.update_one(
        {'email': email},
        {'$set': {'otp': new_otp, 'otp_expires_at': new_expiry}}
    )

    try:
        send_otp_email(email, new_otp)
    except Exception as e:
        return jsonify({'message': 'Failed to resend OTP'}), 500

    return jsonify({'message': 'New OTP has been sent'}), 200


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400

    user = mongo.db.users.find_one({'email': email})
    if not user:
        print(f"Login failed: user {email} not found")
        return jsonify({'message': 'Invalid email or password'}), 401

    if not bcrypt.check_password_hash(user['password'], password):
        print(f"Login failed: incorrect password for user {email}")
        return jsonify({'message': 'Invalid email or password'}), 401

    if not user.get('otp_verified', False):
        print(f"Login failed: email {email} not verified")
        return jsonify({'message': 'Email not verified. Please verify OTP first.'}), 403

    expires = timedelta(hours=1)
    access_token = create_access_token(identity=str(user['_id']), expires_delta=expires)

    user_data = {
        'id': str(user['_id']),
        'username': user['username'],
        'email': user['email'],
        'created_at': user['created_at'].strftime('%Y-%m-%d %H:%M:%S')
    }

    return jsonify({
        'access_token': access_token,
        'data': user_data,
        'message': 'Login successful'
    }), 200

@app.route('/user', methods=['GET'])
@jwt_required()
def get_user():
    user_id = get_jwt_identity()

    user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
    if not user:
        return jsonify({'message': 'User not found'}), 404

    user_data = {
        'id': str(user['_id']),
        'username': user['username'],
        'email': user['email'],
        'created_at': user['created_at'].strftime('%Y-%m-%d %H:%M:%S')
    }

    return jsonify({'data': user_data, 'message': 'User fetched successfully'}), 200

@app.route('/', methods=['GET'])
def helo():
    return jsonify({'msg': 'api is redi parah'})


# === Fungsi tambahan untuk scraping YouTube videos ===
def scrape_youtube_videos(query, collection_name):
    ydl_opts = {
        'quiet': True,
        'extract_flat': True,
        'dump_single_json': True,
        'force_generic_extractor': True
    }
    collection = mongo.db[collection_name]
    with yt_dlp.YoutubeDL(ydl_opts) as ydl:
        result = ydl.extract_info(f"ytsearch20:{query}", download=False)

    saved = []
    skipped = []
    for video in result.get('entries', []):
        title = video.get('title')
        if collection.find_one({"title": title}):
            skipped.append(title)
            continue

        data = {
            "title": title,
            "description": video.get('description', 'Tidak ada deskripsi'),
            "link": f"https://www.youtube.com/watch?v={video.get('id')}",
            "channel": video.get('uploader', 'Tidak diketahui'),
            "location": "Indonesia",
            "scraped_at": datetime.datetime.utcnow()
        }

        result = collection.insert_one(data)
        if result.acknowledged:
            saved.append(title)

    return saved, skipped

# === Route scraping artikel dari website ===
@app.route('/scrape/articles', methods=['GET'])
def scrape_articles():
    url = 'https://web.gogolf.co.id/course'
    headers = {'User-Agent': 'Mozilla/5.0'}
    response = requests.get(url, headers=headers)
    soup = BeautifulSoup(response.text, 'html.parser')

    data = []
    for article in soup.find_all('h3'):
        judul = article.get_text(strip=True)
        if judul:
            data.append({"judul": judul})

    collection = mongo.db['article']
    if data:
        existing_titles = set(doc['judul'] for doc in collection.find({}, {"judul":1}))
        new_data = [d for d in data if d['judul'] not in existing_titles]
        if new_data:
            collection.insert_many(new_data)
            return jsonify({"message": f"{len(new_data)} artikel baru berhasil disimpan ke MongoDB Atlas.", "data": new_data})
        else:
            return jsonify({"message": "Tidak ada artikel baru yang ditemukan."})
    else:
        return jsonify({"message": "Tidak ada data yang ditemukan."}), 404

# === Route scraping video lokasi golf ===
@app.route('/scrape/lokasi', methods=['GET'])
def scrape_lokasi():
    saved, skipped = scrape_youtube_videos("golf course Indonesia", "lokasi")
    return jsonify({
        "message": f"{len(saved)} video lokasi golf berhasil disimpan.",
        "saved_titles": saved,
        "skipped_titles": skipped
    })

# === Route scraping video tutorial golf ===
@app.route('/scrape/tutorial', methods=['GET'])
def scrape_tutorial():
    saved, skipped = scrape_youtube_videos("golf tutorial", "tutorial")
    return jsonify({
        "message": f"{len(saved)} video tutorial golf berhasil disimpan.",
        "saved_titles": saved,
        "skipped_titles": skipped
    })

# === Route get semua articles ===
@app.route('/article', methods=['GET'])
def get_articles():
    collection = mongo.db['article']
    articles = list(collection.find({}, {"_id": 0}))
    return jsonify({"data": articles})

# === Route get semua lokasi ===
@app.route('/lokasi', methods=['GET'])
def get_lokasi():
    collection = mongo.db['lokasi']
    lokasi = list(collection.find({}, {"_id": 0}))
    return jsonify({"data": lokasi})

# === Route get semua tutorial ===
@app.route('/tutorial', methods=['GET'])
def get_tutorial():
    collection = mongo.db['tutorial']
    tutorial = list(collection.find({}, {"_id": 0}))
    return jsonify({"data": tutorial})

@app.route('/barang', methods=['POST'])
def add_single_barang():
    data = request.get_json()

    # Pastikan data ada dan wajib fields ada
    required_fields = ['nama', 'kategori', 'harga', 'link', 'gambar']
    if not data or not all(field in data for field in required_fields):
        return jsonify({'message': 'Data tidak lengkap'}), 400

    # Siapkan data untuk disimpan
    new_barang = {
        'nama': data['nama'],
        'kategori': data['kategori'],
        'harga': data['harga'],
        'link': data['link'],
        'gambar': data['gambar'],
        'created_at': datetime.utcnow()
    }

    # Insert ke MongoDB
    result = mongo.db.barang.insert_one(new_barang)

    return jsonify({'message': 'Produk berhasil disimpan', 'id': str(result.inserted_id)}), 201

@app.route('/barang', methods=['GET'])
def get_all_barang():
    collection = mongo.db.barang
    barang_list = []

    for item in collection.find():
        item['_id'] = str(item['_id'])  # Convert ObjectId to string
        item['created_at'] = item['created_at'].strftime('%Y-%m-%d %H:%M:%S')  # Format datetime
        barang_list.append(item)

    return jsonify({'data': barang_list, 'message': 'Data produk berhasil diambil'}), 200

@app.route('/update-profile', methods=['PUT'])
@jwt_required()
def update_profile():
    user_id = get_jwt_identity()
    data = request.get_json()

    update_fields = {}

    if 'username' in data:
        update_fields['username'] = data['username']
    if 'email' in data:
        update_fields['email'] = data['email']
    if 'password' in data:
        # Hash password sebelum disimpan
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        update_fields['password'] = hashed_password

    if not update_fields:
        return jsonify({'message': 'No data to update'}), 400

    result = mongo.db.users.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': update_fields}
    )

    if result.matched_count == 0:
        return jsonify({'message': 'User not found'}), 404

    return jsonify({'message': 'Profile updated successfully'}), 200

@app.route('/deteksi', methods=['POST'])
@jwt_required()
def deteksi():
    user_id = get_jwt_identity()
    data = request.get_json()

    if not data:
        return jsonify({'message': 'JSON body kosong'}), 400

    label = data.get('label')
    image_base64 = data.get('image')

    if not label or not image_base64:
        return jsonify({'message': 'Field label dan image wajib diisi'}), 400

    try:
        # Decode base64 image
        image_data = base64.b64decode(image_base64.split(',')[-1])
        upload_result = cloudinary.uploader.upload(
            BytesIO(image_data),
            folder="pose_history",
            public_id=f"{user_id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        )

        image_url = upload_result.get('secure_url')

        # Simpan ke MongoDB
        history = {
            'user_id': ObjectId(user_id),
            'label': label,
            'timestamp': datetime.utcnow(),
            'image': image_url
        }
        result = mongo.db.pose_history.insert_one(history)

        return jsonify({'message': 'History pose berhasil disimpan', 'id': str(result.inserted_id)}), 201

    except Exception as e:
        print('Upload/Gagal insert:', e)
        return jsonify({'message': 'Gagal menyimpan history pose'}), 500

@app.route('/deteksi', methods=['GET'])
@jwt_required()
def get_deteksi():
    user_id = get_jwt_identity()

    try:
        history_cursor = mongo.db.pose_history.find({'user_id': ObjectId(user_id)})
        history_list = []

        for h in history_cursor:
            history_list.append({
                'id': str(h['_id']),
                'label': h['label'],
                'timestamp': h['timestamp'].isoformat(),
                'image': h['image']  # Sudah berupa URL dari Cloudinary
            })

        return jsonify({'data': history_list, 'message': 'History pose berhasil diambil'}), 200
    except Exception as e:
        print('Error ambil history:', e)
        return jsonify({'message': 'Gagal mengambil history pose'}), 500
    


@app.route('/auth/google', methods=['POST'])
def google_auth():
    data = request.get_json()
    id_token_string = data.get('id_token')
    email = data.get('email')
    name = data.get('name')
    photo_url = data.get('photo_url')
    
    if not email or not name:
        return jsonify({'message': 'Email dan name wajib diisi'}), 400
    
    # OPSIONAL: Verifikasi ID Token untuk keamanan ekstra
    if id_token_string:
        try:
            # Ganti dengan Client ID dari Google Console
            CLIENT_ID = "751384058788-cms6sjk8ev04rgtrmto9qg4tg2hcauuj.apps.googleusercontent.com"
            idinfo = id_token.verify_oauth2_token(
                id_token_string, 
                requests.Request(), 
                CLIENT_ID
            )
            
            # Pastikan email cocok
            if idinfo['email'] != email:
                return jsonify({'message': 'Email tidak cocok dengan token'}), 400
                
            print("ID Token terverifikasi untuk:", idinfo['email'])
            
        except ValueError as e:
            print("ID Token tidak valid:", e)
            # Bisa tetap lanjut atau return error, tergantung kebutuhan
            # return jsonify({'message': 'Token tidak valid'}), 401
    
    # Cek apakah user sudah ada
    user = mongo.db.users.find_one({'email': email})
    
    if not user:
        # Buat user baru
        new_user = {
            'username': name,
            'email': email,
            'auth_provider': 'google',
            'photo_url': photo_url,  # Simpan foto Google
            'otp_verified': True,
            'created_at': datetime.utcnow()
        }
        result = mongo.db.users.insert_one(new_user)
        user_id = str(result.inserted_id)
        user = new_user
        user['_id'] = result.inserted_id
    else:
        user_id = str(user['_id'])
        # Update foto jika ada
        if photo_url:
            mongo.db.users.update_one(
                {'_id': user['_id']},
                {'$set': {'photo_url': photo_url}}
            )
    
    # Buat JWT token
    expires = timedelta(hours=1)
    access_token = create_access_token(identity=user_id, expires_delta=expires)
    
    user_data = {
        'id': user_id,
        'username': user['username'],
        'email': user['email'],
        'photo_url': user.get('photo_url'),
        'created_at': user['created_at'].strftime('%Y-%m-%d %H:%M:%S')
    }
    
    return jsonify({
        'access_token': access_token,
        'data': user_data,
        'message': 'Login berhasil'
    }), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
