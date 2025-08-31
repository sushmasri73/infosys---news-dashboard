import os
import json
import requests
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from textblob import TextBlob
from datetime import datetime, timedelta

# Ensure the required environment variables are set for Google OAuth
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Initialize Flask app
app = Flask(__name__)
app.config.from_object('config.Config')
db = SQLAlchemy(app)

# --- Database Models ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    email = db.Column(db.String(120), unique=True, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class SearchHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    topic = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

class NewsSource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    source_name = db.Column(db.String(100), nullable=False)
    topic = db.Column(db.String(50), nullable=False)

# --- Routes ---

@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Handles form submission for standard login
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('dashboard'))
        
        return render_template('login.html', error="Invalid username or password")

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            return render_template('login.html', error="Username already exists")
        
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for('login'))
        
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get the full username/email from the session
    full_username = session['username']
    
    # Extract the first name by splitting the email address
    first_name = full_username.split('@')[0]

    VALID_TOPICS = ['business', 'entertainment', 'general', 'health', 'science', 'sports', 'technology']
    return render_template('dashboard.html', username=first_name, topics=VALID_TOPICS)

# --- API Endpoints ---

@app.route('/api/news/<topic>')
def get_news(topic):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # NewsAPI key provided by the user
    api_key = '3f7c6744b0bc4d3cbc661c2118bb9a90'

    # NewsAPI.org URL
    url = f"https://newsapi.org/v2/top-headlines?country=us&category={topic}&apiKey={api_key}"
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        news_data = response.json()
        articles = news_data.get('articles', [])
        
        # Save search history and news sources
        user_id = session['user_id']
        new_search = SearchHistory(user_id=user_id, topic=topic)
        db.session.add(new_search)
        
        for article in articles:
            source_name = article['source']['name']
            new_source = NewsSource(user_id=user_id, source_name=source_name, topic=topic)
            db.session.add(new_source)
        
        db.session.commit()
        
        return jsonify(articles)
    except requests.exceptions.HTTPError as errh:
        # Update the error message to be more user-friendly
        if errh.response.status_code == 401:
            return jsonify({'error': f"HTTP Error: 401 Client Error. The API key is likely invalid or has expired. Please check your config.py file and sign up for a new key at <a href='https://newsapi.org/register' target='_blank'>newsapi.org</a>."}), 401
        return jsonify({'error': f"HTTP Error: {errh}"}), 500
    except requests.exceptions.RequestException as err:
        return jsonify({'error': f"Request Error: {err}"}), 500

@app.route('/api/search')
def search_news():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    keyword = request.args.get('keyword')
    if not keyword:
        return jsonify({'error': 'Please provide a search keyword'}), 400

    api_key = '3f7c6744b0bc4d3cbc661c2118bb9a90'
    url = f"https://newsapi.org/v2/everything?q={keyword}&sortBy=popularity&apiKey={api_key}"
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        news_data = response.json()
        articles = news_data.get('articles', [])

        # Save search history
        user_id = session['user_id']
        new_search = SearchHistory(user_id=user_id, topic=keyword)
        db.session.add(new_search)
        db.session.commit()

        return jsonify(articles)
    except requests.exceptions.HTTPError as errh:
        if errh.response.status_code == 401:
            return jsonify({'error': "HTTP Error: 401 Client Error. Invalid API key."}), 401
        return jsonify({'error': f"HTTP Error: {errh}"}), 500
    except requests.exceptions.RequestException as err:
        return jsonify({'error': f"Request Error: {err}"}), 500

@app.route('/api/sentiment', methods=['POST'])
def analyze_sentiment():
    data = request.json.get('articles', [])
    if not data:
        return jsonify({'error': 'No articles provided'}), 400

    sentiment_counts = {'positive': 0, 'negative': 0, 'neutral': 0}
    
    for article in data:
        text = article.get('title', '') + ' ' + article.get('description', '')
        if not text.strip():
            continue

        analysis = TextBlob(text)
        if analysis.sentiment.polarity > 0.1:
            sentiment_counts['positive'] += 1
        elif analysis.sentiment.polarity < -0.1:
            sentiment_counts['negative'] += 1
        else:
            sentiment_counts['neutral'] += 1
            
    total = sum(sentiment_counts.values())
    if total == 0:
        return jsonify({'positive': 0, 'negative': 0, 'neutral': 0})
        
    sentiment_percentages = {
        'positive': (sentiment_counts['positive'] / total) * 100,
        'negative': (sentiment_counts['negative'] / total) * 100,
        'neutral': (sentiment_counts['neutral'] / total) * 100,
    }

    return jsonify(sentiment_percentages)

@app.route('/api/charts/searches_per_topic')
def searches_per_topic():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user_id = session['user_id']
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=7)

    results = db.session.query(
        SearchHistory.topic,
        db.func.count(SearchHistory.id)
    ).filter(
        SearchHistory.user_id == user_id,
        SearchHistory.timestamp >= start_date,
        SearchHistory.timestamp <= end_date
    ).group_by(
        SearchHistory.topic
    ).all()

    labels = [row[0] for row in results]
    data = [row[1] for row in results]
    
    return jsonify({'labels': labels, 'data': data})

@app.route('/api/charts/source_distribution/<topic>')
def source_distribution(topic):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user_id = session['user_id']
    results = db.session.query(
        NewsSource.source_name,
        db.func.count(NewsSource.id)
    ).filter(
        NewsSource.user_id == user_id,
        NewsSource.topic == topic
    ).group_by(
        NewsSource.source_name
    ).all()
    
    labels = [row[0] for row in results]
    data = [row[1] for row in results]
    
    return jsonify({'labels': labels, 'data': data})


@app.route('/google_login', methods=['POST'])
def google_login():
    try:
        token = request.json['id_token']
        # You MUST replace this placeholder with your actual Google Client ID
        # from the Google Cloud Console for the sign-in to work.
        CLIENT_ID = 'YOUR_GOOGLE_CLIENT_ID'
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), CLIENT_ID)

        email = idinfo['email']
        user = User.query.filter_by(email=email).first()

        if not user:
            username = idinfo.get('name', email.split('@')[0])
            user = User(username=username, email=email)
            db.session.add(user)
            db.session.commit()
            
        session['user_id'] = user.id
        session['username'] = user.username

        return jsonify({'success': True}), 200

    except ValueError:
        return jsonify({'error': 'Invalid token'}), 401
    except KeyError:
        return jsonify({'error': 'Missing token'}), 400

# To run the app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)