Personalized News Dashboard - 

A web application that provides users with a personalized news feed based on their interests and search history. The dashboard leverages the NewsAPI to fetch real-time headlines and performs sentiment analysis on the articles to give users insights into the tone of the news.

Features :

User Authentication: Secure login and registration with username/password.
Google OAuth: Seamless sign-in using your Google account.
Personalized News Feed: Fetches top headlines based on user-selected categories.
Sentiment Analysis: Analyzes news article titles and classifies them as positive, negative, or neutral.
Search History Tracking: Keeps a record of recent search topics to help personalize content.
Interactive Charts: Visualizes news source statistics for a specific topic, showing which sources are most frequently viewed.
Persistent Data Storage: Uses SQLite and SQLAlchemy to store user data, search history, and news source preferences.

Tech Stack : 

Backend: Python, Flask

Frontend: HTML, Bootstrap, Tailwind CSS

Database: SQLite (SQLAlchemy ORM)

APIs: NewsAPI, Google Identity Services

Libraries:

flask: Web framework

flask-sqlalchemy: Database ORM

requests: HTTP library for API calls

textblob: For sentiment analysis

werkzeug: Secure password hashing
