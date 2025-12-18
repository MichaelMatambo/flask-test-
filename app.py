# app.py

import os
import datetime
# 1. Added 'render_template' to the imports
from flask import Flask, jsonify, request, render_template 
from config import Config
from pymongo import MongoClient
from bson.objectid import ObjectId
import requests 
from flask_bcrypt import Bcrypt 
import jwt 
from jwt import ExpiredSignatureError, InvalidTokenError
from datetime import datetime, timedelta, timezone 
from functools import wraps 
from flask_cors import CORS 
from bson.json_util import dumps 

# --- Application Initialization ---

app = Flask(__name__)
app.config.from_object(Config)
CORS(app) 
bcrypt = Bcrypt(app) 

# Initialize MongoDB client
try:
    client = MongoClient(app.config['MONGO_URI'])
    db = client.yelp_clone_db 
except Exception as e:
    print(f"FATAL: Could not connect to MongoDB. Check MONGO_URI in .env. Error: {e}")

businesses_collection = db.businesses
users_collection = db.users
reviews_collection = db.reviews

# --- Utility Functions and Decorators ---

def token_required(f):
    """Decorator to require a valid JWT for accessing the wrapped route."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')

        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1] 
        
        if not token:
            return jsonify({'message': 'Authorization token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = users_collection.find_one({"_id": ObjectId(data['user_id'])})
            
            if not current_user:
                 return jsonify({'message': 'Token user not found'}), 401

        except ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except InvalidTokenError:
            return jsonify({'message': 'Token is invalid'}), 401
        except Exception as e:
            return jsonify({'message': f'Token error: {str(e)}'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

# --- Page Rendering Routes ---

@app.route('/', methods=['GET'])
def root():
    """SERVE THE MAIN LANDING PAGE."""
    # This replaces the JSON status and tells Flask to show your HTML
    return render_template('index.html')

@app.route('/business.html', methods=['GET'])
def business_page():
    """SERVE THE BUSINESS SEARCH/MAP PAGE."""
    return render_template('business.html')

# --- Health Check Route (Moved to /status) ---

@app.route('/status', methods=['GET'])
def status():
    """API endpoint to check server and database connection status."""
    try:
        client.admin.command('ismaster') 
        return jsonify({"status": "Server Running", "db_status": "MongoDB Connected"}), 200
    except Exception as e:
        return jsonify({"status": "Server Running", "db_status": f"MongoDB Error: {e}"}), 500


# --- User Authentication Routes ---

@app.route('/api/users', methods=['POST'])
def register_user():
    """Handles user registration."""
    data = request.get_json()
    required_fields = ['username', 'email', 'password']
    for field in required_fields:
        if not data.get(field):
            return jsonify({"error": f"Missing required field: {field}"}), 400

    username = data['username']
    email = data['email']
    password = data['password']
    
    if len(password) < 8:
          return jsonify({"error": "Password must be at least 8 characters long"}), 400

    if users_collection.find_one({'$or': [{'username': username}, {'email': email}]}):
        return jsonify({"error": "Username or email already exists"}), 409

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user_doc = {
        "username": username,
        "email": email,
        "password_hash": hashed_password,
        "member_since": datetime.now(timezone.utc)
    }

    try:
        result = users_collection.insert_one(user_doc)
        return jsonify({"message": "User registered successfully", "id": str(result.inserted_id)}), 201
    except Exception as e:
        return jsonify({"error": "Failed to register user", "details": str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login_user():
    """Handles user login and issues a JWT."""
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({"error": "Email and password are required"}), 400

    user = users_collection.find_one({"email": data['email']})
    if not user or not bcrypt.check_password_hash(user['password_hash'], data['password']):
        return jsonify({"error": "Invalid email or password"}), 401 

    try:
        payload = {
            'user_id': str(user['_id']), 
            'exp': datetime.now(timezone.utc) + timedelta(days=1), 
            'iat': datetime.now(timezone.utc)
        }
        token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({"message": "Login successful", "token": token, "username": user['username']}), 200
    except Exception as e:
        return jsonify({"error": "Token generation failed", "details": str(e)}), 500

# --- Business Routes ---

@app.route('/api/businesses/map', methods=['GET'])
def get_businesses_for_map():
    """Retrieves business coordinates and details for map markers."""
    try:
        businesses = businesses_collection.find({}, 
            {'_id': 1, 'name': 1, 'latitude': 1, 'longitude': 1, 'category': 1, 
             'avg_rating': 1, 'review_count': 1, 'address': 1, 'city': 1}
        )
        mapped_businesses = []
        for business in businesses:
             if business.get('latitude') is not None and business.get('longitude') is not None:
                mapped_businesses.append({
                    '_id': str(business['_id']),
                    'name': business['name'],
                    'address': business['address'],
                    'city': business['city'],
                    'categories': business.get('category', ''), 
                    'avg_rating': business.get('avg_rating', 0.0),
                    'review_count': business.get('review_count', 0),
                    'location': {'lat': business['latitude'], 'lon': business['longitude']}
                })
        return dumps({"businesses": mapped_businesses}), 200
    except Exception as e:
        return jsonify({"error": "Failed to fetch map data", "details": str(e)}), 500

@app.route('/api/businesses', methods=['GET'])
def get_businesses():
    """Retrieves businesses with search and filtering."""
    search_term = request.args.get('search', '')
    city_filter = request.args.get('city', '')
    category_filter = request.args.get('category', '')
    
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 10))
    skip = (page - 1) * limit
    
    query = {}
    if search_term:
        query['$or'] = [{'name': {'$regex': search_term, '$options': 'i'}},
                        {'address': {'$regex': search_term, '$options': 'i'}},
                        {'category': {'$regex': search_term, '$options': 'i'}}]
    if city_filter:
        query['city'] = {'$regex': city_filter, '$options': 'i'}
    if category_filter:
        query['category'] = {'$regex': category_filter, '$options': 'i'}
        
    try:
        total_count = businesses_collection.count_documents(query)
        cursor = businesses_collection.find(query).skip(skip).limit(limit)
        results = []
        for b in cursor:
            b['_id'] = str(b['_id'])
            b['owner_id'] = str(b.get('owner_id'))
            results.append(b)

        return jsonify({
            "page": page, "total_count": total_count, "businesses": results
        }), 200
    except Exception as e:
        return jsonify({"error": "Failed to retrieve businesses", "details": str(e)}), 500

# --- Review Routes ---

@app.route('/api/reviews', methods=['POST'])
@token_required 
def submit_review(current_user):
    """Allows a logged-in user to submit a review."""
    data = request.get_json()
    try:
        business_oid = ObjectId(data['business_id'])
        review_doc = {
            "business_id": business_oid,
            "user_id": current_user['_id'],
            "username": current_user['username'],
            "rating": int(data['rating']),
            "review_text": data['text'],
            "date_posted": datetime.now(timezone.utc)
        }
        reviews_collection.insert_one(review_doc)
        return jsonify({"message": "Review submitted successfully"}), 201
    except Exception as e:
        return jsonify({"error": "Failed to submit review", "details": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)