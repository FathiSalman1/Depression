from flask import Flask, Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import jwt
import datetime
from functools import wraps
import logging
import json
from werkzeug.utils import secure_filename
import time
from contextlib import contextmanager

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize the Flask application
app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Replace with a secure key in production
app.config['SECRET_KEY'] = app.secret_key
app.config['UPLOAD_FOLDER'] = os.path.abspath('static/uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['DATABASE_TIMEOUT'] = 30  # seconds
app.config['SQLITE_JOURNAL_MODE'] = 'WAL'  # Better concurrency mode

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Enable CORS for API routes
CORS(app, resources={r"/api/*": {"origins": "*"}})


# Database connection management
@contextmanager
def get_db_connection(db_name):
    """Context manager for database connections with retry logic"""
    db_path = f'{db_name}.db'
    retries = 3
    delay = 0.1

    for attempt in range(retries):
        try:
            conn = sqlite3.connect(db_path, timeout=app.config['DATABASE_TIMEOUT'])
            conn.execute(f'PRAGMA journal_mode={app.config["SQLITE_JOURNAL_MODE"]}')
            conn.row_factory = sqlite3.Row
            yield conn
            conn.close()
            break
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e) and attempt < retries - 1:
                time.sleep(delay)
                delay *= 2  # exponential backoff
                continue
            logger.error(f"Database error ({db_name}): {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected database error ({db_name}): {str(e)}")
            raise


def execute_db_query(db_name, query, params=(), commit=False, fetch=False):
    """Helper function to execute database queries with retry logic"""
    with get_db_connection(db_name) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(query, params)
            if commit:
                conn.commit()
            if fetch:
                return cursor.fetchone()
            return cursor
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Query execution failed: {str(e)}")
            raise


# Database initialization
def init_db():
    """Initialize all databases with proper settings"""
    databases = {
        'users': '''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                test_history TEXT DEFAULT '[]',
                last_active TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''',
        'admins': '''
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                profile_image TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''',
        'experts': '''
            CREATE TABLE IF NOT EXISTS experts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                specialization TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        '''
    }

    sample_users = [
        ('John Doe', 'john@example.com', 'password123'),
        ('Jane Smith', 'jane@example.com', 'test456',
         '[{"test_date": "2025-04-20", "score": 15, "result": "Moderate depression"}]')
    ]

    sample_admins = [
        ('admin', 'admin123', 'admin@gmail.com', 'Administrator'),
        ('manager', 'manager456', 'manager@gmail.com', 'Manager')
    ]

    for db_name, schema in databases.items():
        try:
            # Create tables
            execute_db_query(db_name, schema, commit=True)

            # Add sample data
            if db_name == 'users':
                for user in sample_users:
                    hashed_pw = generate_password_hash(user[2], method='pbkdf2:sha256')
                    try:
                        if len(user) == 3:
                            execute_db_query(
                                db_name,
                                'INSERT INTO users (name, email, password, last_active) VALUES (?, ?, ?, ?)',
                                (user[0], user[1], hashed_pw, datetime.datetime.utcnow()),
                                commit=True
                            )
                        else:
                            execute_db_query(
                                db_name,
                                'INSERT INTO users (name, email, password, test_history, last_active) VALUES (?, ?, ?, ?, ?)',
                                (user[0], user[1], hashed_pw, user[3], datetime.datetime.utcnow()),
                                commit=True
                            )
                    except sqlite3.IntegrityError:
                        logger.warning(f"User {user[1]} already exists")

            elif db_name == 'admins':
                for admin in sample_admins:
                    hashed_pw = generate_password_hash(admin[1], method='pbkdf2:sha256')
                    try:
                        execute_db_query(
                            db_name,
                            'INSERT INTO admins (username, password, email, name) VALUES (?, ?, ?, ?)',
                            (admin[0], hashed_pw, admin[2], admin[3]),
                            commit=True
                        )
                    except sqlite3.IntegrityError:
                        logger.warning(f"Admin {admin[0]} already exists")

        except sqlite3.Error as e:
            logger.error(f"Error initializing {db_name} database: {str(e)}")


# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# JWT authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            token = token.split(" ")[1]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])

            user = execute_db_query(
                'users',
                'SELECT * FROM users WHERE email = ?',
                (data['email'],),
                fetch=True
            )

            if not user:
                return jsonify({'message': 'User not found'}), 401

            # Update last active time
            execute_db_query(
                'users',
                'UPDATE users SET last_active = ? WHERE email = ?',
                (datetime.datetime.utcnow(), data['email']),
                commit=True
            )

            return f(user, *args, **kwargs)

        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        except sqlite3.Error as e:
            logger.error(f"Database error during token validation: {str(e)}")
            return jsonify({'message': 'Database error'}), 500
        except Exception as e:
            logger.error(f"Unexpected error during token validation: {str(e)}")
            return jsonify({'message': 'Token validation failed'}), 401

    return decorated


# API Blueprint
api_bp = Blueprint('api', __name__)


@api_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({'message': 'Missing required fields'}), 400
    if len(password) < 6:
        return jsonify({'message': 'Password must be at least 6 characters'}), 400

    try:
        # Check if email exists
        existing_user = execute_db_query(
            'users',
            'SELECT 1 FROM users WHERE email = ?',
            (email,),
            fetch=True
        )

        if existing_user:
            return jsonify({'message': 'Email already registered'}), 400

        # Create new user
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        execute_db_query(
            'users',
            'INSERT INTO users (name, email, password, last_active) VALUES (?, ?, ?, ?)',
            (name, email, hashed_password, datetime.datetime.utcnow()),
            commit=True
        )

        # Generate token
        token = jwt.encode({
            'email': email,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({'token': token}), 201

    except sqlite3.Error as e:
        logger.error(f"Database error during registration: {str(e)}")
        if "database is locked" in str(e):
            return jsonify({'message': 'Server is busy. Please try again later.'}), 503
        return jsonify({'message': 'Registration failed'}), 500
    except Exception as e:
        logger.error(f"Unexpected error during registration: {str(e)}")
        return jsonify({'message': 'Registration failed'}), 500


@api_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Missing required fields'}), 400

    try:
        user = execute_db_query(
            'users',
            'SELECT * FROM users WHERE email = ?',
            (email,),
            fetch=True
        )

        if user and check_password_hash(user['password'], password):
            # Update last active time
            execute_db_query(
                'users',
                'UPDATE users SET last_active = ? WHERE email = ?',
                (datetime.datetime.utcnow(), email),
                commit=True
            )

            # Generate token
            token = jwt.encode({
                'email': email,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }, app.config['SECRET_KEY'], algorithm="HS256")

            return jsonify({
                'status': 'success',
                'token': token,
                'user': {
                    'email': user['email'],
                    'name': user['name']
                }
            }), 200

        return jsonify({'message': 'Incorrect email or password'}), 401

    except sqlite3.Error as e:
        logger.error(f"Database error during login: {str(e)}")
        if "database is locked" in str(e):
            return jsonify({'message': 'Server is busy. Please try again later.'}), 503
        return jsonify({'message': 'Login failed'}), 500
    except Exception as e:
        logger.error(f"Unexpected error during login: {str(e)}")
        return jsonify({'message': 'Login failed'}), 500


@api_bp.route('/profile', methods=['GET'])
@token_required
def profile(current_user):
    return jsonify({
        'name': current_user['name'],
        'email': current_user['email'],
        'test_history': current_user['test_history']
    }), 200


@api_bp.route('/logout', methods=['POST'])
@token_required
def logout(current_user):
    return jsonify({'message': 'Logged out successfully'}), 200


@api_bp.route('/submit_test', methods=['POST'])
@token_required
def submit_test(current_user):
    data = request.get_json()
    score = data.get('score')
    result = data.get('result')
    if score is None or not result:
        return jsonify({'message': 'Missing required fields'}), 400
    try:
        test_history = json.loads(current_user['test_history'])
        new_test = {
            'test_date': datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
            'score': score,
            'result': result
        }
        test_history.append(new_test)

        execute_db_query(
            'users',
            'UPDATE users SET test_history = ? WHERE email = ?',
            (json.dumps(test_history), current_user['email']),
            commit=True
        )

        return jsonify({'message': 'Test submitted successfully'}), 200
    except sqlite3.Error as e:
        logger.error(f"Database error during test submission: {str(e)}")
        return jsonify({'message': 'Failed to submit test'}), 500
    except Exception as e:
        logger.error(f"Unexpected error during test submission: {str(e)}")
        return jsonify({'message': 'Failed to submit test'}), 500


# Backend Blueprint
backend_bp = Blueprint('backend', __name__, template_folder='templates')


@backend_bp.route('/dashboard')
def dashboard():
    if 'username' not in session:
        logger.warning("No username in session, redirecting to login")
        flash('Please log in to access the dashboard', 'danger')
        return redirect(url_for('backend.login'))

    try:
        admin = execute_db_query(
            'admins',
            'SELECT * FROM admins WHERE username = ?',
            (session['username'],),
            fetch=True
        )

        if not admin:
            logger.error(f"No admin found for username: {session['username']}")
            session.pop('username', None)
            session.pop('user_id', None)
            flash('Admin account not found. Please log in again.', 'danger')
            return redirect(url_for('backend.login'))

        # Get user statistics
        user_stats = execute_db_query(
            'users',
            '''
            SELECT 
                COUNT(*) as user_count,
                SUM(json_array_length(test_history)) as test_count,
                SUM(CASE WHEN created_at >= datetime('now', '-30 days') THEN 1 ELSE 0 END) as new_user_count,
                SUM(CASE WHEN last_active >= datetime('now', '-7 days') THEN 1 ELSE 0 END) as active_user_count
            FROM users
            ''',
            fetch=True
        )

        # Get recent users
        users = execute_db_query(
            'users',
            'SELECT id, name, email, test_history, created_at FROM users'
        ).fetchall()

        # Get experts
        experts = execute_db_query(
            'experts',
            'SELECT id, name, email, specialization, created_at FROM experts'
        ).fetchall()

        logger.debug(f"Rendering dashboard with admin: {admin['username']}")
        return render_template('dashboard.html',
                               admin=admin,
                               user_count=user_stats['user_count'],
                               test_count=user_stats['test_count'],
                               new_user_count=user_stats['new_user_count'],
                               active_user_count=user_stats['active_user_count'],
                               users=users,
                               experts=experts)

    except sqlite3.Error as e:
        logger.error(f"Database error in dashboard: {str(e)}")
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('backend.login'))
    except Exception as e:
        logger.error(f"Unexpected error in dashboard: {str(e)}")
        flash(f'Unexpected error: {str(e)}', 'danger')
        return redirect(url_for('backend.login'))


# ... [rest of your backend routes with the same pattern of using execute_db_query] ...

# Frontend Blueprint
frontend_bp = Blueprint('frontend', __name__, template_folder='templates')


@frontend_bp.route('/')
def index():
    return render_template('index.html')


@frontend_bp.route('/about')
def about():
    return render_template('about.html')


@frontend_bp.route('/contact')
def contact():
    return render_template('contact.html')


@frontend_bp.route('/departments')
def departments():
    return render_template('departments.html')


@frontend_bp.route('/doctors')
def doctors():
    return render_template('doctors.html')


@frontend_bp.route('/test')
def depression_test():
    return render_template('test.html')


# Register Blueprints
app.register_blueprint(api_bp, url_prefix='/api')
app.register_blueprint(backend_bp, url_prefix='/@dmin')
app.register_blueprint(frontend_bp)

# Initialize the databases
with app.app_context():
    init_db()

if __name__ == '__main__':
    app.run(debug=True)