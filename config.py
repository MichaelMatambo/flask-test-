# config.py

import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Flask Settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a_very_secret_fallback_key'

    # MongoDB Settings
    # IMPORTANT: Store your actual connection string in a .env file
    MONGO_URI = os.environ.get('MONGO_URI') 
    
    # Check if URI is available for safety
    if MONGO_URI is None:
        raise ValueError("MONGO_URI is not set in environment variables or .env file.")