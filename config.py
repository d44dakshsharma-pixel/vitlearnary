import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Common configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key')
    MAX_CONTENT_LENGTH = 25 * 1024 * 1024
    ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'ppt', 'pptx', 'txt', 'zip'}
    
    # Environment-specific configuration
    if os.environ.get('FLASK_ENV') == 'production':
        MONGO_URI = os.getenv('MONGO_URI')
        UPLOAD_FOLDER = '/tmp/uploads'  # Use temp directory in production
        DEBUG = False
    else:
        # Development defaults
        MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/vitlearnary')
        UPLOAD_FOLDER = 'uploads'
        DEBUG = True