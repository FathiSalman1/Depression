from flask import Flask, render_template, request, redirect, url_for, flash
from database import db, User

app = Flask(__name__)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  # SQLite database file
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key'  # Required for flashing messages

# Initialize the database with the app
db.init_app(app)

# Create the database and tables
with app.app_context():
    db.create_all()


# Routes
@app.route('/')
def login():
    return render_template('rtl/index.html')


@app.route('/index')
def index():
    return render_template('rtl/index.html')


@app.route('/test')
def test():
    return render_template('rtl/test.html')


if __name__ == '__main__':
    app.run(debug=True)