import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_strong_and_secret_key_here'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///users.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Get these from Google Cloud Console
    GOOGLE_CLIENT_ID = "362210886857-v1i1vvn7fj9k0qvp95hj15jghof854pf.apps.googleusercontent.com"
    GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET") or "YOUR_GOOGLE_CLIENT_SECRET"
    
    # Get this from NewsAPI.org
    NEWS_API_KEY = os.environ.get("NEWS_API_KEY") or "3f7c6744b0bc4d3cbc661c2118bb9a90YO"

    GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
