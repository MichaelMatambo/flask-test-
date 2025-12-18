# app.py

import os
import datetime
from flask import Flask, jsonify, request
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
from bson.json_util import dumps # <-- NEW: Import for safe MongoDB JSON serialization

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

# Geocoding function (placeholder, not used in API)
def geocode_address(address, city, state, zip_code):
    full_address = f"{address}, {city}, {state} {zip_code}"
    # Using Nominatim Public Geocoding service
    url = "https://nominatim.openstreetmap.org/search"
    params = {'q': full_address, 'format': 'json', 'limit': 1}
    
    try:
        response = requests.get(url, params=params, headers={'User-Agent': 'InjectaReview-App/1.0'})
        response.raise_for_status() 
        data = response.json()
        
        if data:
            return float(data[0]['lat']), float(data[0]['lon'])
        else:
            return None, None
            
    except requests.RequestException as e:
        print(f"Geocoding failed for address '{full_address}': {e}")
        return None, None


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


# --- Health Check Routes ---

@app.route('/', methods=['GET'])
def root():
    """HANDLE THE ROOT PATH / BY DIRECTING TO THE STATUS CHECK."""
    # This resolves the 404 issue on the primary URL
    return status() 

@app.route('/status', methods=['GET'])
def status():
    """Checks server and database connection status."""
    try:
        client.admin.command('ismaster') 
        return jsonify({"status": "Server Running", "db_status": "MongoDB Connected"}), 200
    except Exception as e:
        return jsonify({"status": "Server Running", "db_status": f"MongoDB Error: {e}"}), 500


# --- User Authentication Routes ---

@app.route('/api/users', methods=['POST'])
def register_user():
    """Handles user registration, hashing the password securely."""
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
        
        return jsonify({
            "message": "User registered successfully",
            "id": str(result.inserted_id),
            "username": username
        }), 201
        
    except Exception as e:
        return jsonify({"error": "Failed to register user", "details": str(e)}), 500


@app.route('/api/auth/login', methods=['POST'])
def login_user():
    """Handles user login, validates password, and issues a JWT."""
    data = request.get_json()

    if not data or not data.get('email') or not data.get('password'):
        return jsonify({"error": "Email and password are required"}), 400

    email = data['email']
    password = data['password']

    user = users_collection.find_one({"email": email})
    
    if not user or not bcrypt.check_password_hash(user['password_hash'], password):
        return jsonify({"error": "Invalid email or password"}), 401 

    try:
        payload = {
            'user_id': str(user['_id']), 
            'exp': datetime.now(timezone.utc) + timedelta(days=1), 
            'iat': datetime.now(timezone.utc)
        }
        
        token = jwt.encode(
            payload, 
            app.config['SECRET_KEY'], 
            algorithm='HS256'
        )
        
        return jsonify({
            "message": "Login successful",
            "token": token,
            "username": user['username']
        }), 200

    except Exception as e:
        return jsonify({"error": "Token generation failed", "details": str(e)}), 500


# --- Business Routes ---

@app.route('/api/businesses/map', methods=['GET']) # <-- NEW ROUTE FOR MAP
def get_businesses_for_map():
    """
    Retrieves a list of all businesses, specifically including their ID, name, 
    and geographic location for map display. This endpoint is called once on 
    frontend load to populate all markers.
    """
    try:
        # Fetch all businesses, projecting only the necessary fields for the map popup and marker
        businesses = businesses_collection.find({}, 
            {'_id': 1, 'name': 1, 'latitude': 1, 'longitude': 1, 'categories': 1, 
             'avg_rating': 1, 'review_count': 1, 'address': 1, 'city': 1}
        )
        
        # Restructure data to match the frontend's OpenLayers expectation (location: {lat, lon})
        mapped_businesses = []
        for business in businesses:
             # Only include businesses with valid coordinates
             if business.get('latitude') is not None and business.get('longitude') is not None:
                mapped_businesses.append({
                    '_id': str(business['_id']),
                    'name': business['name'],
                    'address': business['address'],
                    'city': business['city'],
                    'categories': business.get('category', ''), # Use 'category' field name from DB
                    'avg_rating': business.get('avg_rating', 0.0),
                    'review_count': business.get('review_count', 0),
                    # Structure coordinates as expected by the OpenLayers frontend
                    'location': {
                        'lat': business['latitude'],
                        'lon': business['longitude']
                    }
                })

        # Use dumps() for correct ObjectId serialization
        return dumps({"businesses": mapped_businesses}), 200
        
    except Exception as e:
        print(f"Error fetching businesses for map: {e}")
        return jsonify({"error": "Failed to fetch map data", "details": str(e)}), 500


@app.route('/api/businesses', methods=['GET'])
def get_businesses():
    """
    Retrieves a list of businesses, supporting search, filtering, and pagination.
    """
    search_term = request.args.get('search', '')
    city_filter = request.args.get('city', '')
    category_filter = request.args.get('category', '')
    
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 10))
    skip = (page - 1) * limit
    
    query = {}

    if search_term:
        query['$or'] = [
            {'name': {'$regex': search_term, '$options': 'i'}},
            {'address': {'$regex': search_term, '$options': 'i'}},
            {'category': {'$regex': search_term, '$options': 'i'}}
        ]
        
    if city_filter:
        query['city'] = {'$regex': city_filter, '$options': 'i'}

    if category_filter:
        query['category'] = {'$regex': category_filter, '$options': 'i'}
        
    try:
        total_count = businesses_collection.count_documents(query)
        
        cursor = businesses_collection.find(query).skip(skip).limit(limit)
        
        results = []
        for business in cursor:
            # Format the result: Convert ObjectId fields to string and include coordinates
            results.append({
                '_id': str(business['_id']),
                'owner_id': str(business.get('owner_id')),
                'name': business['name'],
                'address': business['address'],
                'city': business['city'],
                'state': business['state'],
                'zip_code': business['zip_code'],
                # --- INCLUDED LAT/LONG IN RESPONSE ---
                'latitude': business.get('latitude'),
                'longitude': business.get('longitude'),
                # -------------------------------------
                'category': business['category'],
                'phone': business['phone'],
                'avg_rating': business.get('avg_rating', 0.0),
                'review_count': business.get('review_count', 0),
            })

        return jsonify({
            "message": "Businesses retrieved successfully",
            "page": page,
            "limit": limit,
            "total_count": total_count,
            "total_pages": (total_count + limit - 1) // limit, 
            "businesses": results
        }), 200

    except Exception as e:
        return jsonify({"error": "Failed to retrieve businesses", "details": str(e)}), 500


@app.route('/api/businesses/<business_id>', methods=['GET'])
def get_single_business(business_id):
    """Retrieves a single business profile and all its associated reviews."""
    try:
        business_oid = ObjectId(business_id)
    except Exception:
        return jsonify({"error": "Invalid business ID format"}), 400

    business = businesses_collection.find_one({"_id": business_oid})
    
    if not business:
        return jsonify({"error": "Business not found"}), 404

    # Fetch Associated Reviews (Newest first)
    reviews_cursor = reviews_collection.find({"business_id": business_oid}).sort("date_posted", -1)
    
    reviews = []
    for review in reviews_cursor:
        reviews.append({
            '_id': str(review['_id']),
            'user_id': str(review['user_id']),
            'username': review['username'],
            'rating': review['rating'],
            'review_text': review['review_text'],
            'date_posted': review['date_posted'].isoformat()
        })
    
    # Combine data for final response
    business_data = {
        '_id': str(business['_id']),
        'owner_id': str(business.get('owner_id')),
        'name': business['name'],
        'address': business['address'],
        'city': business['city'],
        'state': business['state'],
        'zip_code': business['zip_code'],
        # --- INCLUDED LAT/LONG IN RESPONSE ---
        'latitude': business.get('latitude'),
        'longitude': business.get('longitude'),
        # -------------------------------------
        'category': business['category'],
        'phone': business['phone'],
        'avg_rating': business.get('avg_rating', 0.0),
        'review_count': business.get('review_count', 0),
        'reviews': reviews
    }
    
    return jsonify({
        "message": "Business profile retrieved successfully",
        "business": business_data
    }), 200


@app.route('/api/businesses', methods=['POST'])
@token_required 
def register_business(current_user):
    """Registers a new business, requiring coordinates from the user."""
    data = request.get_json()
    
    required_fields = ['name', 'address', 'city', 'state', 'zip_code', 'categories', 'phone_number', 'latitude', 'longitude']
    for field in required_fields:
        if not data.get(field):
            return jsonify({"error": f"Missing required field: {field}"}), 400

    # The frontend is sending categories as a comma-separated string,
    # but the existing check expects a list.
    # We will adjust the backend to handle the string from the frontend.
    categories_str = data.get('categories')
    if not categories_str or not isinstance(categories_str, str):
        return jsonify({"error": "Categories must be provided as a comma-separated string"}), 400
    
    categories_list = [c.strip() for c in categories_str.split(',') if c.strip()]
    if not categories_list:
        return jsonify({"error": "Category list cannot be empty"}), 400
        
    try:
        # Convert coordinates to float
        latitude = float(data['latitude'])
        longitude = float(data['longitude'])
    except ValueError:
        return jsonify({"error": "Latitude and longitude must be valid numbers"}), 400

    # --- FINAL ANTI-DUPLICATION CHECK (FIXING MISBEHAVIOR) ---
    if businesses_collection.find_one({'name': data['name'], 'address': data['address']}):
        return jsonify({"error": "A business with this exact name and address already exists."}), 409 
    # -----------------------------------------------------------

    # Prepare the business document
    business_doc = {
        "owner_id": current_user['_id'],
        "name": data['name'],
        "address": data['address'],
        "city": data['city'],
        "state": data['state'],
        "zip_code": data['zip_code'],
        "category": categories_list, # Store as a list
        "phone": data['phone_number'],
        "latitude": latitude,
        "longitude": longitude,
        "website": data.get('website', ''), 
        "avg_rating": 0.0,
        "review_count": 0
    }

    try:
        result = businesses_collection.insert_one(business_doc)
        
        return jsonify({
            "message": "Business registered successfully (coordinates stored)", 
            "id": str(result.inserted_id)
        }), 201
        
    except Exception as e:
        return jsonify({"error": "Failed to register business", "details": str(e)}), 500


@app.route('/api/reviews', methods=['POST'])
@token_required 
def submit_review(current_user):
    """
    Allows a logged-in user to submit a review for a business.
    """
    data = request.get_json()
    
    required_fields = ['business_id', 'rating', 'text']
    for field in required_fields:
        if not data.get(field):
            return jsonify({"error": f"Missing required field: {field}"}), 400

    try:
        business_oid = ObjectId(data['business_id'])
        rating = int(data['rating'])
        review_text = data['text'] # Match frontend field name
        
        if not 1 <= rating <= 5:
              return jsonify({"error": "Rating must be between 1 and 5 stars"}), 400
              
    except Exception:
        return jsonify({"error": "Invalid business ID or rating format"}), 400

    business = businesses_collection.find_one({"_id": business_oid})
    if not business:
        return jsonify({"error": "Business not found"}), 404
        
    existing_review = reviews_collection.find_one({
        "business_id": business_oid,
        "user_id": current_user['_id']
    })
    if existing_review:
        return jsonify({"error": "You have already reviewed this business."}), 409


    review_doc = {
        "business_id": business_oid,
        "user_id": current_user['_id'],
        "username": current_user['username'],
        "rating": rating,
        "review_text": review_text, # Match database field name
        "date_posted": datetime.now(timezone.utc)
    }

    try:
        review_result = reviews_collection.insert_one(review_doc)
        
        # Update Business Average Rating and Count using aggregation
        pipeline = [
            {'$match': {'business_id': business_oid}},
            {'$group': {
                '_id': '$business_id',
                'avg_rating': {'$avg': '$rating'},
                'review_count': {'$sum': 1}
            }}
        ]
        
        aggregation_result = list(reviews_collection.aggregate(pipeline))

        new_stats = {}
        if aggregation_result:
            new_stats = aggregation_result[0]
            
            businesses_collection.update_one(
                {"_id": business_oid},
                {'$set': {
                    "avg_rating": round(new_stats['avg_rating'], 2),
                    "review_count": new_stats['review_count']
                }}
            )

        return jsonify({
            "message": "Review submitted and business rating updated successfully",
            "review_id": str(review_result.inserted_id),
            "new_avg_rating": round(new_stats.get('avg_rating'), 2) if aggregation_result else 0.0
        }), 201
        
    except Exception as e:
        return jsonify({"error": "Failed to submit review or update business", "details": str(e)}), 500


# --- Main Execution ---

if __name__ == '__main__':
    if not os.environ.get('MONGO_URI'):
          print("ERROR: MONGO_URI is not set. Please check your .env file and config.py.")
    
    app.run(debug=True)