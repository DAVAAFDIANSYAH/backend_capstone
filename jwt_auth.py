# # jwt_auth.py
# import jwt
# import datetime
# from flask import request, jsonify
# from functools import wraps
# from pymongo import MongoClient
# from config import JWT_SECRET, MONGO_URI, DB_NAME
# from werkzeug.security import check_password_hash

# client = MongoClient(MONGO_URI)
# db = client[DB_NAME]
# users_col = db["users"]

# def generate_token(username):
#     payload = {
#         "user": username,
#         "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
#     }
#     return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

# def jwt_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         auth_header = request.headers.get("Authorization")
#         if not auth_header or not auth_header.startswith("Bearer "):
#             return jsonify({"message": "Token is missing"}), 401
#         token = auth_header.split(" ")[1]

#         try:
#             payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
#             request.user = payload["user"]
#         except jwt.ExpiredSignatureError:
#             return jsonify({"message": "Token expired"}), 401
#         except jwt.InvalidTokenError:
#             return jsonify({"message": "Invalid token"}), 401
#         return f(*args, **kwargs)
#     return decorated

# def login():
#     data = request.get_json()
#     username = data.get("username")
#     password = data.get("password")

#     user = users_col.find_one({"username": username})
#     if user and check_password_hash(user["password"], password):
#         token = generate_token(username)
#         return jsonify({"token": token})
#     return jsonify({"message": "Invalid credentials"}), 401
