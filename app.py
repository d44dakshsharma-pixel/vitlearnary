from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
from flask_pymongo import PyMongo
from bson import ObjectId
from werkzeug.utils import secure_filename
from config import Config
from datetime import datetime
import hashlib
import uuid
import os
from io import BytesIO
from functools import wraps
from aws_config import aws_config
import boto3
from botocore.exceptions import ClientError

app = Flask(__name__, static_folder='.', static_url_path='')
app.config.from_object(Config)
print("MONGO_URI being used:", app.config.get('MONGO_URI'))

CORS(app, origins=["*"], supports_credentials=True, methods=["GET", "POST", "PUT", "DELETE"])

# Fix for both local and production
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# Fix MongoDB connection
app.config['MONGO_URI'] = os.getenv('MONGO_URI', 'mongodb+srv://Daksh-123:Daksh-123@cluster0.stvk1yo.mongodb.net/vitlearnary?retryWrites=true&w=majority')

try:
    mongo = PyMongo(app)
    print("MongoDB connected successfully!")
except Exception as e:
    print(f"MongoDB connection error: {e}")
    # Create a dummy mongo object to prevent crashes
    class DummyMongo:
        def __getattr__(self, name):
            return self
        def __call__(self, *args, **kwargs):
            return self
    mongo = DummyMongo()

# Password hashing function
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Initialize database
# Initialize database
def init_db():
    with app.app_context():
        # Create indexes
        mongo.db.users.create_index('email', unique=True)
        
        # Add default admin user if not exists
        try:
            admin_user = mongo.db.users.find_one({'email': 'daksh.24bsa10265@vitbhopal.ac.in'})
            if not admin_user:
                hashed_password = hash_password('admin123')
                mongo.db.users.insert_one({
                    'name': 'Daksh Sharma',
                    'email': 'daksh.24bsa10265@vitbhopal.ac.in',
                    'password': hashed_password,
                    'role': 'admin',
                    'joined_date': datetime.utcnow()
                })
                print("Admin user created: daksh.24bsa10265@vitbhopal.ac.in / admin123")
            else:
                # Ensure existing admin user has admin role
                if admin_user.get('role') != 'admin':
                    mongo.db.users.update_one(
                        {'email': 'daksh.24bsa10265@vitbhopal.ac.in'},
                        {'$set': {'role': 'admin'}}
                    )
                    print("Updated existing user to admin role")
                else:
                    print("Admin user already exists")
                
        except Exception as e:
            print(f"Error creating admin user: {e}")
        
        # Create uploads directory if it doesn't exist
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])

# Helper functions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            # Extract user ID from token
            user_id = token.replace('Bearer ', '').strip()
            user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
            
            if not user:
                return jsonify({'message': 'Token is invalid!'}), 401
                
            # Convert ObjectId to string for JSON serialization
            user['id'] = str(user['_id'])
            request.current_user = user
        except Exception as e:
            return jsonify({'message': 'Token is invalid!', 'error': str(e)}), 401
            
        return f(*args, **kwargs)
    
    return decorated

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            # Extract user ID from token
            user_id = token.replace('Bearer ', '').strip()
            user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
            
            if not user:
                return jsonify({'message': 'Token is invalid!'}), 401
            
            # Check if user is admin
            if user.get('role') != 'admin':
                return jsonify({'message': 'Admin access required!'}), 403
                
            # Convert ObjectId to string for JSON serialization
            user['id'] = str(user['_id'])
            request.current_user = user
        except Exception as e:
            return jsonify({'message': 'Token is invalid!', 'error': str(e)}), 401
            
        return f(*args, **kwargs)
    
    return decorated

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# Serve the main HTML page at root
@app.route('/')
def serve_app():
    return send_from_directory('.', 'index.html')

# API info endpoint
@app.route('/api/')
def api_home():
    return jsonify({
        'message': 'VITLearnary API is running!', 
        'version': '1.0',
        'database': 'MongoDB Atlas',
        'endpoints': {
            'auth': ['/api/auth/register', '/api/auth/login'],
            'resources': ['/api/resources', '/api/resources/upload', '/api/resources/<id>/download'],
            'user': ['/api/resources/user', '/api/dashboard/stats']
        }
    })

@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        if not data or not all(key in data for key in ['name', 'email', 'password', 'role']):
            return jsonify({'message': 'Missing required fields'}), 400
        
        # Check if email is from VIT Bhopal domain
        if not data['email'].endswith('@vitbhopal.ac.in'):
            return jsonify({'message': 'Only official VIT Bhopal email addresses (@vitbhopal.ac.in) are allowed'}), 400
        
        if data['role'] not in ['student', 'faculty']:
            return jsonify({'message': 'Invalid role. Must be student or faculty'}), 400
        
        print(f"DEBUG: Registration attempt for: {data['email']}")
        
        # Check if user already exists - ONLY check for the exact email
        existing_user = mongo.db.users.find_one({'email': data['email']})
        if existing_user:
            print(f"DEBUG: User already exists with email: {data['email']}")
            return jsonify({'message': 'User with this email already exists'}), 400
        else:
            print(f"DEBUG: Email {data['email']} is available")
        
        # Check if this is the admin user
        role = data['role']
        if data['email'] == 'daksh.24bsa10265@vitbhopal.ac.in':
            role = 'admin'
            print(f"DEBUG: Admin user detected: {data['email']}")
        
        # Hash password and create new user
        hashed_password = hash_password(data['password'])
        user_data = {
            'name': data['name'],
            'email': data['email'],
            'password': hashed_password,
            'role': role,
            'joined_date': datetime.utcnow()
        }
        
        print(f"DEBUG: Creating new user: {user_data}")
        
        result = mongo.db.users.insert_one(user_data)
        user_id = str(result.inserted_id)
        
        print(f"DEBUG: User created successfully with ID: {user_id}")
        
        # Get the new user (without password)
        user = mongo.db.users.find_one({'_id': result.inserted_id}, {'password': 0})
        user['id'] = user_id
        del user['_id']
        
        return jsonify({
            'message': 'User created successfully',
            'user': user,
            'token': f'Bearer {user_id}'
        }), 201
        
    except Exception as e:
        print(f"DEBUG: Registration error: {str(e)}")
        return jsonify({'message': 'Registration failed', 'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        if not data or not all(key in data for key in ['email', 'password']):
            return jsonify({'message': 'Missing email or password'}), 400
        
        # Check if email is from VIT Bhopal domain
        if not data['email'].endswith('@vitbhopal.ac.in'):
            return jsonify({'message': 'Only official VIT Bhopal email addresses (@vitbhopal.ac.in) are allowed'}), 400
        
        # Hash the provided password for comparison
        hashed_password = hash_password(data['password'])
        
        print(f"DEBUG: Login attempt for: {data['email']}")
        print(f"DEBUG: Looking for user in database...")
        
        user = mongo.db.users.find_one({'email': data['email']})
        
        if not user:
            print(f"DEBUG: No user found with email: {data['email']}")
            return jsonify({'message': 'Invalid email or password'}), 401
        
        print(f"DEBUG: User found: {user['email']}")
        print(f"DEBUG: Checking password...")
        
        # Compare hashed passwords
        if user['password'] != hashed_password:
            print("DEBUG: Password doesn't match")
            return jsonify({'message': 'Invalid email or password'}), 401
        
        print("DEBUG: Login successful!")
        
        # Create response without password
        user_response = {
            'id': str(user['_id']),
            'name': user['name'],
            'email': user['email'],
            'role': user['role'],
            'joined_date': user['joined_date']
        }
        
        return jsonify({
            'message': 'Login successful',
            'user': user_response,
            'token': f'Bearer {user_response["id"]}'
        })
        
    except Exception as e:
        print(f"DEBUG: Login error: {str(e)}")
        return jsonify({'message': 'Login failed', 'error': str(e)}), 500

@app.route('/api/resources', methods=['GET'])
def get_resources():
    try:
        # Get query parameters for filtering
        search = request.args.get('search', '')
        course = request.args.get('course', '')
        semester = request.args.get('semester', '')
        resource_type = request.args.get('type', '')
        
        print(f"DEBUG: Fetching resources with filters - search: '{search}', course: '{course}', semester: '{semester}', type: '{resource_type}'")
        
        # Build query for MongoDB
        query = {}
        
        if search:
            query['$or'] = [
                {'title': {'$regex': search, '$options': 'i'}},
                {'description': {'$regex': search, '$options': 'i'}},
                {'subject': {'$regex': search, '$options': 'i'}}
            ]
        
        if course:
            query['course'] = course
            
        if semester:
            query['semester'] = semester
            
        if resource_type:
            query['type'] = resource_type
        
        print(f"DEBUG: MongoDB query: {query}")
        
        # First, try to get resources with aggregation (with uploader info)
        resources = []
        try:
            # Get resources with uploader info using aggregation
            pipeline = [
                {'$match': query},
                {'$lookup': {
                    'from': 'users',
                    'localField': 'uploader_id',
                    'foreignField': '_id',
                    'as': 'uploader'
                }},
                {'$unwind': {'path': '$uploader', 'preserveNullAndEmptyArrays': True}},
                {'$sort': {'upload_date': -1}},
                {'$project': {
                    'title': 1,
                    'description': 1,
                    'course': 1,
                    'semester': 1,
                    'subject': 1,
                    'type': 1,
                    'file_name': 1,
                    'file_size': 1,
                    'upload_date': 1,
                    'download_count': 1,
                    'rating': 1,
                    'file_url': 1,
                    'original_filename': 1,
                    'uploader_name': '$uploader.name',
                    'file_size_mb': {'$divide': ['$file_size', 1024 * 1024]}
                }}
            ]
            
            resources = list(mongo.db.resources.aggregate(pipeline))
            print(f"DEBUG: Found {len(resources)} resources using aggregation")
            
        except Exception as agg_error:
            print(f"DEBUG: Aggregation failed, trying simple query: {agg_error}")
            # Fallback to simple query if aggregation fails
            resources = list(mongo.db.resources.find(query).sort('upload_date', -1))
            print(f"DEBUG: Found {len(resources)} resources using simple query")
        
        # Process resources for response
        processed_resources = []
        for resource in resources:
            try:
                # Convert ObjectId to string for JSON serialization
                resource_data = {
                    'id': str(resource['_id']),
                    'title': resource.get('title', 'Untitled'),
                    'description': resource.get('description', 'No description'),
                    'course': resource.get('course', ''),
                    'semester': resource.get('semester', ''),
                    'subject': resource.get('subject', ''),
                    'type': resource.get('type', 'other'),
                    'file_name': resource.get('file_name', ''),
                    'file_size': resource.get('file_size', 0),
                    'upload_date': resource.get('upload_date', datetime.utcnow()),
                    'download_count': resource.get('download_count', 0),
                    'rating': resource.get('rating', 0),
                    'file_url': resource.get('file_url', ''),
                    'original_filename': resource.get('original_filename', resource.get('file_name', 'file')),
                    'uploader_name': resource.get('uploader_name', 'Unknown'),
                    'file_size_mb': round(resource.get('file_size_mb', resource.get('file_size', 0) / (1024 * 1024)), 2)
                }
                
                # If uploader_name is not set, try to get it from embedded user data
                if resource_data['uploader_name'] == 'Unknown' and 'uploader' in resource:
                    if isinstance(resource['uploader'], list) and len(resource['uploader']) > 0:
                        resource_data['uploader_name'] = resource['uploader'][0].get('name', 'Unknown')
                    elif isinstance(resource['uploader'], dict):
                        resource_data['uploader_name'] = resource['uploader'].get('name', 'Unknown')
                
                processed_resources.append(resource_data)
                
            except Exception as e:
                print(f"DEBUG: Error processing resource {resource.get('_id', 'unknown')}: {e}")
                continue
        
        print(f"DEBUG: Returning {len(processed_resources)} processed resources")
        return jsonify(processed_resources)
        
    except Exception as e:
        print(f"ERROR: Failed to fetch resources: {str(e)}")
        # Return empty array instead of failing
        return jsonify([])

@app.route('/api/resources/upload', methods=['POST'])
@token_required
def upload_resource():
    try:
        if 'file' not in request.files:
            return jsonify({'message': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'message': 'No file selected'}), 400
        
        # Check if S3 is available
        s3_client = aws_config.get_s3_client()
        if s3_client is None:
            return jsonify({'message': 'File upload service temporarily unavailable'}), 503
        
        if file and allowed_file(file.filename):
            # Get form data
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            course = request.form.get('course', '').strip()
            semester = request.form.get('semester', '').strip()
            subject = request.form.get('subject', '').strip()
            resource_type = request.form.get('type', '').strip()
            
            if not all([title, description, course, semester, subject, resource_type]):
                return jsonify({'message': 'All fields are required'}), 400
            
            # Generate unique filename for S3
            original_filename = secure_filename(file.filename)
            s3_filename = f"{uuid.uuid4().hex}_{original_filename}"
            
            # Upload to S3
            s3_client = aws_config.get_s3_client()
            
            try:
                s3_client.upload_fileobj(
                    file,
                    aws_config.bucket_name,
                    s3_filename,
                    ExtraArgs={
                        'ContentType': file.content_type,
                        'ACL': 'public-read'
                    }
                )
                
                # Generate public URL
                file_url = f"https://{aws_config.bucket_name}.s3.{aws_config.region_name}.amazonaws.com/{s3_filename}"
                
                # Save resource metadata to MongoDB
                resource_data = {
                    'title': title,
                    'description': description,
                    'course': course,
                    'semester': semester,
                    'subject': subject,
                    'type': resource_type,
                    'file_name': s3_filename,
                    'original_filename': original_filename,
                    'file_url': file_url,
                    'file_size': file.content_length,  # Use content_length from file object
                    'upload_date': datetime.utcnow(),
                    'uploader_id': ObjectId(request.current_user['id']),
                    'download_count': 0,
                    'rating': 0
                }
                
                result = mongo.db.resources.insert_one(resource_data)
                
                return jsonify({
                    'message': 'Resource uploaded successfully to S3',
                    'file_url': file_url
                })
                
            except ClientError as e:
                return jsonify({'message': 'S3 upload failed', 'error': str(e)}), 500
        
        else:
            return jsonify({'message': 'File type not allowed'}), 400
            
    except Exception as e:
        return jsonify({'message': 'Upload failed', 'error': str(e)}), 500

@app.route('/api/resources/user', methods=['GET'])
@token_required
def get_user_resources():
    try:
        user_id = ObjectId(request.current_user['id'])
        resources = []
        
        try:
            # Try aggregation first
            pipeline = [
                {'$match': {'uploader_id': user_id}},
                {'$lookup': {
                    'from': 'users',
                    'localField': 'uploader_id',
                    'foreignField': '_id',
                    'as': 'uploader'
                }},
                {'$unwind': {'path': '$uploader', 'preserveNullAndEmptyArrays': True}},
                {'$sort': {'upload_date': -1}},
                {'$project': {
                    'title': 1,
                    'description': 1,
                    'course': 1,
                    'semester': 1,
                    'subject': 1,
                    'type': 1,
                    'file_name': 1,
                    'file_size': 1,
                    'upload_date': 1,
                    'download_count': 1,
                    'rating': 1,
                    'file_url': 1,
                    'original_filename': 1,
                    'uploader_name': '$uploader.name',
                    'file_size_mb': {'$divide': ['$file_size', 1024 * 1024]}
                }}
            ]
            
            resources = list(mongo.db.resources.aggregate(pipeline))
            
        except Exception as agg_error:
            print(f"DEBUG: User resources aggregation failed: {agg_error}")
            # Fallback to simple query
            resources = list(mongo.db.resources.find({'uploader_id': user_id}).sort('upload_date', -1))
        
        processed_resources = []
        for resource in resources:
            try:
                resource_data = {
                    'id': str(resource['_id']),
                    'title': resource.get('title', 'Untitled'),
                    'description': resource.get('description', 'No description'),
                    'course': resource.get('course', ''),
                    'semester': resource.get('semester', ''),
                    'subject': resource.get('subject', ''),
                    'type': resource.get('type', 'other'),
                    'file_name': resource.get('file_name', ''),
                    'file_size': resource.get('file_size', 0),
                    'upload_date': resource.get('upload_date', datetime.utcnow()),
                    'download_count': resource.get('download_count', 0),
                    'rating': resource.get('rating', 0),
                    'file_url': resource.get('file_url', ''),
                    'original_filename': resource.get('original_filename', resource.get('file_name', 'file')),
                    'uploader_name': resource.get('uploader_name', 'You'),
                    'file_size_mb': round(resource.get('file_size_mb', resource.get('file_size', 0) / (1024 * 1024)), 2)
                }
                
                if resource_data['uploader_name'] == 'You' and 'uploader' in resource:
                    if isinstance(resource['uploader'], list) and len(resource['uploader']) > 0:
                        resource_data['uploader_name'] = resource['uploader'][0].get('name', 'You')
                    elif isinstance(resource['uploader'], dict):
                        resource_data['uploader_name'] = resource['uploader'].get('name', 'You')
                
                processed_resources.append(resource_data)
                
            except Exception as e:
                print(f"DEBUG: Error processing user resource: {e}")
                continue
        
        return jsonify(processed_resources)
        
    except Exception as e:
        print(f"ERROR: Failed to fetch user resources: {str(e)}")
        return jsonify([])

@app.route('/api/dashboard/stats', methods=['GET'])
@token_required
def get_dashboard_stats():
    try:
        user_id = ObjectId(request.current_user['id'])
        
        # User's upload count
        uploads_count = mongo.db.resources.count_documents({'uploader_id': user_id})
        
        # User's total downloads (resources uploaded by user that were downloaded)
        # First get all resources uploaded by the user
        user_resources = list(mongo.db.resources.find({'uploader_id': user_id}, {'_id': 1}))
        user_resource_ids = [resource['_id'] for resource in user_resources]
        
        # Count downloads for these resources - handle case where downloads collection doesn't exist
        downloads_count = 0
        if user_resource_ids:
            try:
                # Check if downloads collection exists
                if 'downloads' in mongo.db.list_collection_names():
                    downloads_count = mongo.db.downloads.count_documents({
                        'resource_id': {'$in': user_resource_ids}
                    })
            except Exception as e:
                print(f"Downloads count error (collection might not exist): {e}")
                downloads_count = 0  # Default to 0 if downloads collection doesn't exist
        
        # User's average rating - handle case where rating field might not exist
        rating_avg = 0.0
        try:
            rating_result = list(mongo.db.resources.aggregate([
                {'$match': {'uploader_id': user_id}},
                {'$addFields': {
                    'rating_value': {'$ifNull': ['$rating', 0]}  # Handle missing rating field
                }},
                {'$match': {'rating_value': {'$gt': 0}}},
                {'$group': {'_id': None, 'avg_rating': {'$avg': '$rating_value'}}}
            ]))
            
            if rating_result:
                rating_avg = round(float(rating_result[0]['avg_rating']), 1)
        except Exception as e:
            print(f"Rating calculation error: {e}")
            rating_avg = 0.0
        
        # Total contributors (users who have uploaded at least one resource)
        contributors_count = 0
        try:
            contributors = mongo.db.resources.distinct('uploader_id')
            contributors_count = len(contributors) if contributors else 0
        except Exception as e:
            print(f"Contributors count error: {e}")
            contributors_count = 0
        
        return jsonify({
            'uploads_count': uploads_count,
            'downloads_count': downloads_count,
            'rating_avg': rating_avg,
            'contributors_count': contributors_count
        })
        
    except Exception as e:
        print(f"Dashboard stats error: {str(e)}")
        # Return default values instead of failing
        return jsonify({
            'uploads_count': 0,
            'downloads_count': 0,
            'rating_avg': 0.0,
            'contributors_count': 0
        })

@app.route('/api/resources/<resource_id>/download', methods=['POST'])
@token_required
def download_resource(resource_id):
    try:
        # Get resource metadata from MongoDB
        resource = mongo.db.resources.find_one({'_id': ObjectId(resource_id)})
        
        if not resource:
            return jsonify({'message': 'Resource not found'}), 404
        
        # Update download count
        mongo.db.resources.update_one(
            {'_id': ObjectId(resource_id)},
            {'$inc': {'download_count': 1}}
        )
        
        # Record download
        mongo.db.downloads.insert_one({
            'user_id': ObjectId(request.current_user['id']),
            'resource_id': ObjectId(resource_id),
            'download_date': datetime.utcnow()
        })
        
        # Generate a presigned URL that forces download
        s3_client = aws_config.get_s3_client()
        presigned_url = s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': aws_config.bucket_name,
                'Key': resource['file_name'],
                'ResponseContentDisposition': f'attachment; filename="{resource["original_filename"]}"'
            },
            ExpiresIn=3600  # 1 hour expiration
        )
        
        return jsonify({
            'message': 'Download ready',
            'download_url': presigned_url,
            'filename': resource['original_filename']
        })
        
    except Exception as e:
        return jsonify({'message': 'Download failed', 'error': str(e)}), 500

# Health check endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        # Test MongoDB connection
        mongo.db.command('ping')
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'uploads_folder': 'exists' if os.path.exists(app.config['UPLOAD_FOLDER']) else 'missing'
        })
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

# Debug endpoint to test connection
@app.route('/api/debug', methods=['GET'])
def debug_endpoint():
    return jsonify({
        'message': 'Debug endpoint working',
        'timestamp': datetime.utcnow().isoformat(),
        'headers': dict(request.headers),
        'method': request.method
    })

# Test route to check database connection
@app.route('/api/debug/db', methods=['GET'])
def debug_db():
    try:
        # Test database connection
        users_count = mongo.db.users.count_documents({})
        # Remove the limit to see ALL users
        users = list(mongo.db.users.find({}, {'password': 0}))
        
        # Convert ObjectId to string for JSON serialization
        users_list = []
        for user in users:
            user_data = {
                'id': str(user['_id']),
                'name': user['name'],
                'email': user['email'],
                'role': user['role'],
                'joined_date': user.get('joined_date', 'N/A')
            }
            users_list.append(user_data)
        
        return jsonify({
            'database_status': 'connected',
            'users_count': users_count,
            'total_users_shown': len(users_list),
            'users': users_list
        })
    except Exception as e:
        return jsonify({
            'database_status': 'error',
            'error': str(e)
        }), 500
    
# Route to check specifically for VIT Bhopal users
@app.route('/api/debug/vit-users', methods=['GET'])
def debug_vit_users():
    try:
        # Find only @vitbhopal.ac.in users
        vit_users = list(mongo.db.users.find(
            {'email': {'$regex': '@vitbhopal.ac.in$'}}, 
            {'password': 0}
        ))
        
        # Convert ObjectId to string
        users_list = []
        for user in vit_users:
            user_data = {
                'id': str(user['_id']),
                'name': user['name'],
                'email': user['email'],
                'role': user['role'],
                'joined_date': user.get('joined_date', 'N/A')
            }
            users_list.append(user_data)
        
        return jsonify({
            'vit_users_count': len(users_list),
            'vit_users': users_list
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/debug/resources', methods=['GET'])
def debug_resources():
    try:
        # Check if resources collection exists and has data
        collections = mongo.db.list_collection_names()
        resources_count = mongo.db.resources.count_documents({}) if 'resources' in collections else 0
        
        # Get a few sample resources
        sample_resources = []
        if resources_count > 0:
            sample_resources = list(mongo.db.resources.find().limit(3))
            for resource in sample_resources:
                resource['id'] = str(resource['_id'])
                del resource['_id']
        
        return jsonify({
            'collections': collections,
            'resources_count': resources_count,
            'sample_resources': sample_resources
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
# Admin endpoint to delete resource
@app.route('/api/admin/resources/<resource_id>', methods=['DELETE'])
@token_required
@admin_required
def admin_delete_resource(resource_id):
    try:
        # Get resource from MongoDB
        resource = mongo.db.resources.find_one({'_id': ObjectId(resource_id)})
        
        if not resource:
            return jsonify({'message': 'Resource not found'}), 404
        
        # Delete file from S3 bucket
        s3_client = aws_config.get_s3_client()
        try:
            s3_client.delete_object(
                Bucket=aws_config.bucket_name,
                Key=resource['file_name']
            )
            print(f"DEBUG: Deleted file from S3: {resource['file_name']}")
        except ClientError as e:
            print(f"DEBUG: S3 deletion error (file might not exist): {e}")
        
        # Delete resource from MongoDB
        mongo.db.resources.delete_one({'_id': ObjectId(resource_id)})
        
        # Delete related downloads
        mongo.db.downloads.delete_many({'resource_id': ObjectId(resource_id)})
        
        return jsonify({'message': 'Resource deleted successfully'})
        
    except Exception as e:
        return jsonify({'message': 'Failed to delete resource', 'error': str(e)}), 500

# Admin endpoint to get all users
@app.route('/api/admin/users', methods=['GET'])
@token_required
@admin_required
def admin_get_users():
    try:
        users = list(mongo.db.users.find({}, {'password': 0}).sort('joined_date', -1))
        
        users_list = []
        for user in users:
            user_data = {
                'id': str(user['_id']),
                'name': user['name'],
                'email': user['email'],
                'role': user['role'],
                'joined_date': user.get('joined_date', 'N/A')
            }
            users_list.append(user_data)
        
        return jsonify(users_list)
        
    except Exception as e:
        return jsonify({'message': 'Failed to fetch users', 'error': str(e)}), 500

# Admin endpoint to delete user
@app.route('/api/admin/users/<user_id>', methods=['DELETE'])
@token_required
@admin_required
def admin_delete_user(user_id):
    try:
        # Prevent admin from deleting themselves
        if user_id == request.current_user['id']:
            return jsonify({'message': 'Cannot delete your own account'}), 400
        
        # Check if user exists
        user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        # Delete user's resources from S3 and MongoDB
        user_resources = list(mongo.db.resources.find({'uploader_id': ObjectId(user_id)}))
        
        s3_client = aws_config.get_s3_client()
        for resource in user_resources:
            try:
                # Delete from S3
                s3_client.delete_object(
                    Bucket=aws_config.bucket_name,
                    Key=resource['file_name']
                )
            except ClientError as e:
                print(f"DEBUG: S3 deletion error for resource {resource['file_name']}: {e}")
        
        # Delete user's resources from MongoDB
        mongo.db.resources.delete_many({'uploader_id': ObjectId(user_id)})
        
        # Delete user's download records
        mongo.db.downloads.delete_many({'user_id': ObjectId(user_id)})
        
        # Delete user
        mongo.db.users.delete_one({'_id': ObjectId(user_id)})
        
        return jsonify({'message': 'User and all associated data deleted successfully'})
        
    except Exception as e:
        return jsonify({'message': 'Failed to delete user', 'error': str(e)}), 500

# Admin endpoint to update user role
@app.route('/api/admin/users/<user_id>/role', methods=['PUT'])
@token_required
@admin_required
def admin_update_user_role(user_id):
    try:
        data = request.get_json()
        new_role = data.get('role')
        
        if not new_role or new_role not in ['student', 'faculty']:
            return jsonify({'message': 'Valid role (student/faculty) required'}), 400
        
        # Prevent admin from changing their own role
        if user_id == request.current_user['id']:
            return jsonify({'message': 'Cannot change your own role'}), 400
        
        # Update user role
        result = mongo.db.users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'role': new_role}}
        )
        
        if result.modified_count == 0:
            return jsonify({'message': 'User not found or role unchanged'}), 404
        
        return jsonify({'message': 'User role updated successfully'})
        
    except Exception as e:
        return jsonify({'message': 'Failed to update user role', 'error': str(e)}), 500

# Debug endpoint to check if current user is admin
@app.route('/api/debug/admin-check', methods=['GET'])
@token_required
def debug_admin_check():
    is_admin = request.current_user.get('role') == 'admin'
    return jsonify({
        'user_id': request.current_user['id'],
        'email': request.current_user['email'],
        'role': request.current_user.get('role'),
        'is_admin': is_admin
    })

@app.route('/api/admin/cleanup-orphaned', methods=['POST'])
@token_required
@admin_required
def cleanup_orphaned_resources():
    """Clean up resources where S3 file no longer exists"""
    try:
        s3_client = aws_config.get_s3_client()
        
        # Get all resources from database
        resources = list(mongo.db.resources.find({}))
        deleted_count = 0
        
        for resource in resources:
            resource_id = str(resource['_id'])
            s3_key = resource['file_name']
            
            # Check if file exists in S3
            try:
                s3_client.head_object(Bucket=aws_config.bucket_name, Key=s3_key)
                # File exists, skip
                continue
            except ClientError as e:
                if e.response['Error']['Code'] == '404':
                    # File doesn't exist in S3, delete from database
                    mongo.db.resources.delete_one({'_id': resource['_id']})
                    # Also delete download records
                    mongo.db.downloads.delete_many({'resource_id': resource['_id']})
                    deleted_count += 1
                    print(f"Deleted orphaned resource: {resource['title']}")
                else:
                    # Other error, log it
                    print(f"Error checking S3 for {s3_key}: {e}")
        
        return jsonify({
            'message': f'Cleaned up {deleted_count} orphaned resources',
            'deleted_count': deleted_count
        })
        
    except Exception as e:
        return jsonify({'message': 'Cleanup failed', 'error': str(e)}), 500

if __name__ == '__main__':
    print("Initializing VITLearnary with MongoDB...")
    init_db()
    
    # Get port from environment variable (for production)
    port = int(os.environ.get("PORT", 5000))
    
    print("MongoDB initialized successfully!")
    print(f"Server starting on port: {port}")
    app.run(host='0.0.0.0', port=port, debug=False)