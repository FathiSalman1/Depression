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
from threading import Lock
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize the Flask application
app = Flask(__name__)
app.secret_key = os.urandom(24).hex()
app.config['SECRET_KEY'] = app.secret_key
app.config['UPLOAD_FOLDER'] = os.path.abspath('static/uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Enable CORS for API routes
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Rate limiter
limiter = Limiter(app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

# Database locks
user_db_lock = Lock()
admin_db_lock = Lock()
expert_db_lock = Lock()

# Database connection helpers
def get_user_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL;')
    conn.execute('PRAGMA busy_timeout=5000;')
    return conn

def get_admin_db_connection():
    conn = sqlite3.connect('admins.db')
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL;')
    conn.execute('PRAGMA busy_timeout=5000;')
    return conn

def get_expert_db_connection():
    conn = sqlite3.connect('experts.db')
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL;')
    conn.execute('PRAGMA busy_timeout=5000;')
    return conn

# Database initialization
def init_db():
    def column_exists(cursor, table_name, column_name):
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = [info[1] for info in cursor.fetchall()]
        return column_name in columns

    # Initialize users.db
    with sqlite3.connect('users.db') as conn:
        conn.execute('PRAGMA journal_mode=WAL;')
        conn.execute('PRAGMA busy_timeout=5000;')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                test_history TEXT DEFAULT '[]',
                last_active TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        if not column_exists(cursor, 'users', 'last_active'):
            cursor.execute('ALTER TABLE users ADD COLUMN last_active TIMESTAMP')
        hashed_password_user1 = generate_password_hash('password123', method='pbkdf2:sha256')
        try:
            cursor.execute('INSERT INTO users (name, email, password, last_active) VALUES (?, ?, ?, ?)',
                           ('John Doe', 'john@example.com', hashed_password_user1, datetime.datetime.utcnow()))
        except sqlite3.IntegrityError:
            logger.warning("User 'john@example.com' already exists")
        hashed_password_user2 = generate_password_hash('test456', method='pbkdf2:sha256')
        sample_test_history = '[{"test_date": "2025-04-20", "score": 15, "result": "Moderate depression"}]'
        try:
            cursor.execute('INSERT INTO users (name, email, password, test_history, last_active) VALUES (?, ?, ?, ?, ?)',
                           ('Jane Smith', 'jane@example.com', hashed_password_user2, sample_test_history, datetime.datetime.utcnow()))
        except sqlite3.IntegrityError:
            logger.warning("User 'jane@example.com' already exists")
        conn.commit()

    # Initialize admins.db
    with sqlite3.connect('admins.db') as conn:
        conn.execute('PRAGMA journal_mode=WAL;')
        conn.execute('PRAGMA busy_timeout=5000;')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                profile_image TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        if not column_exists(cursor, 'admins', 'profile_image'):
            cursor.execute('ALTER TABLE admins ADD COLUMN profile_image TEXT')
        hashed_password_admin = generate_password_hash('admin123', method='pbkdf2:sha256')
        try:
            cursor.execute('INSERT INTO admins (username, password, email, name) VALUES (?, ?, ?, ?)',
                           ('admin', hashed_password_admin, 'admin@gmail.com', 'Administrator'))
        except sqlite3.IntegrityError:
            logger.warning("Admin 'admin' already exists")
        hashed_password_admin2 = generate_password_hash('manager456', method='pbkdf2:sha256')
        try:
            cursor.execute('INSERT INTO admins (username, password, email, name) VALUES (?, ?, ?, ?)',
                           ('manager', hashed_password_admin2, 'manager@gmail.com', 'Manager'))
        except sqlite3.IntegrityError:
            logger.warning("Admin 'manager' already exists")
        conn.commit()

    # Initialize experts.db
    with sqlite3.connect('experts.db') as conn:
        conn.execute('PRAGMA journal_mode=WAL;')
        conn.execute('PRAGMA busy_timeout=5000;')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS experts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                specialization TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()

# Helper function for file extensions
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
            with get_user_db_connection() as conn:
                c = conn.cursor()
                c.execute('SELECT * FROM users WHERE email = ?', (data['email'],))
                current_user = c.fetchone()
                if current_user:
                    c.execute('UPDATE users SET last_active = ? WHERE email = ?',
                             (datetime.datetime.utcnow(), data['email']))
                    conn.commit()
                if not current_user:
                    return jsonify({'message': 'User not found'}), 401
        except jwt.ExpiredSignatureError:
            logger.error("Token has expired")
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError as e:
            logger.error(f"Invalid token: {e}")
            return jsonify({'message': 'Token is invalid'}), 401
        except sqlite3.OperationalError as e:
            logger.error(f"Database operational error during token validation: {e}")
            return jsonify({'message': 'Database is temporarily unavailable. Please try again.'}), 503
        except sqlite3.Error as e:
            logger.error(f"Database error during token validation: {e}")
            return jsonify({'message': f'Database error: {str(e)}'}), 500
        return f(current_user, *args, **kwargs)
    return decorated

# API Blueprint
api_bp = Blueprint('api', __name__)

@api_bp.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
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
        with user_db_lock:
            with get_user_db_connection() as conn:
                c = conn.cursor()
                hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
                c.execute('INSERT INTO users (name, email, password, last_active) VALUES (?, ?, ?, ?)',
                          (name, email, hashed_password, datetime.datetime.utcnow()))
                conn.commit()
        token = jwt.encode({
            'email': email,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'token': token}), 201
    except sqlite3.IntegrityError:
        return jsonify({'message': 'Email already registered'}), 400
    except sqlite3.OperationalError as e:
        logger.error(f"Database operational error during registration: {e}")
        return jsonify({'message': 'Database is temporarily unavailable. Please try again.'}), 503
    except sqlite3.Error as e:
        logger.error(f"Database error during registration: {e}")
        return jsonify({'message': f'Database error: {str(e)}'}), 500

@api_bp.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'message': 'Missing required fields'}), 400
    try:
        with get_user_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM users WHERE email = ?', (email,))
            user = c.fetchone()
            if user and check_password_hash(user['password'], password):
                c.execute('UPDATE users SET last_active = ? WHERE email = ?',
                         (datetime.datetime.utcnow(), email))
                conn.commit()
            if user and check_password_hash(user['password'], password):
                token = jwt.encode({
                    'email': email,
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
                }, app.config['SECRET_KEY'], algorithm="HS256")
                return jsonify({'token': token}), 200
            return jsonify({'message': 'Incorrect email or password'}), 401
    except sqlite3.OperationalError as e:
        logger.error(f"Database operational error during login: {e}")
        return jsonify({'message': 'Database is temporarily unavailable. Please try again.'}), 503
    except sqlite3.Error as e:
        logger.error(f"Database error during login: {e}")
        return jsonify({'message': f'Database error: {str(e)}'}), 500

@api_bp.route('/profile', methods=['GET'])
@token_required
def profile(current_user):
    return jsonify({
        'name': current_user['name'],
        'email': current_user['email'],
        'test_history': json.loads(current_user['test_history'])
    }), 200

@api_bp.route('/logout', methods=['POST'])
@token_required
def logout(current_user):
    return jsonify({'message': 'Logged out successfully'}), 200

@api_bp.route('/submit_test', methods=['POST'])
@token_required
@limiter.limit("5 per minute")
def submit_test(current_user):
    data = request.get_json()
    score = data.get('score')
    result = data.get('result')
    if score is None or not result:
        return jsonify({'message': 'Missing required fields'}), 400
    try:
        with user_db_lock:
            with get_user_db_connection() as conn:
                c = conn.cursor()
                test_history = json.loads(current_user['test_history'])
                new_test = {
                    'test_date': datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                    'score': score,
                    'result': result
                }
                test_history.append(new_test)
                c.execute('UPDATE users SET test_history = ? WHERE email = ?',
                         (json.dumps(test_history), current_user['email']))
                conn.commit()
        return jsonify({'message': 'Test submitted successfully'}), 200
    except sqlite3.OperationalError as e:
        logger.error(f"Database operational error during test submission: {e}")
        return jsonify({'message': 'Database is temporarily unavailable. Please try again.'}), 503
    except sqlite3.Error as e:
        logger.error(f"Database error during test submission: {e}")
        return jsonify({'message': f'Database error: {str(e)}'}), 500

# Backend Blueprint
backend_bp = Blueprint('backend', __name__, template_folder='templates')

@backend_bp.route('/dashboard')
def dashboard():
    if 'username' not in session:
        logger.warning("No username in session, redirecting to login")
        flash('Please log in to access the dashboard', 'danger')
        return redirect(url_for('backend.login'))
    try:
        with get_admin_db_connection() as conn:
            admin = conn.execute('SELECT * FROM admins WHERE username = ?', (session['username'],)).fetchone()
        if not admin:
            logger.error(f"No admin found for username: {session['username']}")
            session.pop('username', None)
            session.pop('user_id', None)
            flash('Admin account not found. Please log in again.', 'danger')
            return redirect(url_for('backend.login'))
        with get_user_db_connection() as conn:
            user_count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
            users = conn.execute('SELECT test_history FROM users').fetchall()
            test_count = sum(len(json.loads(user['test_history'])) for user in users)
            thirty_days_ago = datetime.datetime.utcnow() - datetime.timedelta(days=30)
            new_user_count = conn.execute('SELECT COUNT(*) FROM users WHERE created_at >= ?',
                                        (thirty_days_ago,)).fetchone()[0]
            seven_days_ago = datetime.datetime.utcnow() - datetime.timedelta(days=7)
            active_user_count = conn.execute('SELECT COUNT(*) FROM users WHERE last_active >= ?',
                                           (seven_days_ago,)).fetchone()[0]
            users = conn.execute('SELECT id, name, email, test_history, created_at FROM users').fetchall()
        with get_expert_db_connection() as conn:
            experts = conn.execute('SELECT id, name, email, specialization, created_at FROM experts').fetchall()
        logger.debug(f"Rendering dashboard with admin: {admin['username']}, users: {user_count}, tests: {test_count}")
        return render_template('dashboard.html',
                             admin=admin,
                             user_count=user_count,
                             test_count=test_count,
                             new_user_count=new_user_count,
                             active_user_count=active_user_count,
                             users=users,
                             experts=experts)
    except sqlite3.OperationalError as e:
        logger.error(f"Database operational error in dashboard: {e}")
        flash('Database is temporarily unavailable. Please try again.', 'danger')
        return redirect(url_for('backend.login'))
    except sqlite3.Error as e:
        logger.error(f"Database error in dashboard: {e}")
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('backend.login'))
    except Exception as e:
        logger.error(f"Unexpected error in dashboard: {e}")
        flash(f'Unexpected error: {str(e)}', 'danger')
        return redirect(url_for('backend.login'))

@backend_bp.route('/edit-profile', methods=['GET', 'POST'])
def edit_profile():
    if 'username' not in session:
        logger.warning("No username in session for edit-profile, redirecting to login")
        flash('Please log in to access this page', 'danger')
        return redirect(url_for('backend.login'))
    try:
        with get_admin_db_connection() as conn:
            admin = conn.execute('SELECT * FROM admins WHERE username = ?', (session['username'],)).fetchone()
        if not admin:
            logger.warning(f"No admin found for username: {session['username']}")
            flash('Admin not found', 'danger')
            return redirect(url_for('backend.login'))
        logger.debug(f"Edit profile for admin: {admin['username']}, email: {admin['email']}, profile_image: {admin['profile_image']}")
        if request.method == 'POST':
            name = request.form.get('name')
            email = request.form.get('email')
            password = request.form.get('password')
            profile_image = request.files.get('profile_image')
            if not name or not email:
                flash('Name and email are required', 'danger')
                return render_template('edit-profile.html', admin=admin)
            try:
                with admin_db_lock:
                    with get_admin_db_connection() as conn:
                        c = conn.cursor()
                        image_path = admin['profile_image']
                        if profile_image and allowed_file(profile_image.filename):
                            filename = secure_filename(profile_image.filename)
                            unique_filename = f"{admin['id']}_{filename}"
                            save_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                            logger.debug(f"Saving profile image to filesystem: {save_path}")
                            profile_image.save(save_path)
                            image_path = f"/static/uploads/{unique_filename}?v={int(time.time())}"
                            logger.debug(f"Storing image path in database: {image_path}")
                        if password:
                            if len(password) < 6:
                                flash('Password must be at least 6 characters', 'danger')
                                return render_template('edit-profile.html', admin=admin)
                            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
                            c.execute('UPDATE admins SET name = ?, email = ?, password = ?, profile_image = ? WHERE username = ?',
                                     (name, email, hashed_password, image_path, session['username']))
                        else:
                            c.execute('UPDATE admins SET name = ?, email = ?, profile_image = ? WHERE username = ?',
                                     (name, email, image_path, session['username']))
                        conn.commit()
                        admin = conn.execute('SELECT * FROM admins WHERE username = ?', (session['username'],)).fetchone()
                flash('Profile updated successfully', 'success')
                return redirect(url_for('backend.dashboard'))
            except sqlite3.IntegrityError as e:
                logger.error(f"Integrity error in edit-profile: {str(e)}")
                flash('Email already registered', 'danger')
                return render_template('edit-profile.html', admin=admin)
            except sqlite3.OperationalError as e:
                logger.error(f"Database operational error in edit-profile: {e}")
                flash('Database is temporarily unavailable. Please try again.', 'danger')
                return render_template('edit-profile.html', admin=admin)
            except sqlite3.Error as e:
                logger.error(f"Database error in edit-profile: {e}")
                flash(f'Database error: {str(e)}', 'danger')
                return render_template('edit-profile.html', admin=admin)
            except OSError as e:
                logger.error(f"File save error in edit-profile: {str(e)}")
                flash(f'Error saving profile image: {str(e)}', 'danger')
                return render_template('edit-profile.html', admin=admin)
            except Exception as e:
                logger.error(f"Unexpected error in edit-profile: {str(e)}")
                flash(f'Unexpected error: {str(e)}', 'danger')
                return render_template('edit-profile.html', admin=admin)
        return render_template('edit-profile.html', admin=admin)
    except sqlite3.OperationalError as e:
        logger.error(f"Database operational error in edit-profile (GET): {e}")
        flash('Database is temporarily unavailable. Please try again.', 'danger')
        return redirect(url_for('backend.dashboard'))
    except sqlite3.Error as e:
        logger.error(f"Database error in edit-profile (GET): {e}")
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('backend.dashboard'))
    except Exception as e:
        logger.error(f"Unexpected error in edit-profile (GET): {e}")
        flash(f'Unexpected error: {str(e)}', 'danger')
        return redirect(url_for('backend.dashboard'))

@backend_bp.route('/add-expert', methods=['GET', 'POST'])
def add_expert():
    if 'username' not in session:
        logger.warning("No username in session for add-expert, redirecting to login")
        flash('Please log in to access this page', 'danger')
        return redirect(url_for('backend.login'))
    try:
        with get_admin_db_connection() as conn:
            admin = conn.execute('SELECT * FROM admins WHERE username = ?', (session['username'],)).fetchone()
        if not admin:
            logger.warning(f"No admin found for username: {session['username']}")
            flash('Admin not found', 'danger')
            return redirect(url_for('backend.login'))
        if request.method == 'POST':
            name = request.form.get('name')
            email = request.form.get('email')
            password = request.form.get('password')
            specialization = request.form.get('specialization')
            if not name or not email or not password or not specialization:
                flash('All fields are required', 'danger')
                return render_template('add-expert.html', admin=admin)
            if len(password) < 6:
                flash('Password must be at least 6 characters', 'danger')
                return render_template('add-expert.html', admin=admin)
            try:
                with expert_db_lock:
                    with get_expert_db_connection() as conn:
                        c = conn.cursor()
                        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
                        c.execute('INSERT INTO experts (name, email, password, specialization) VALUES (?, ?, ?, ?)',
                                  (name, email, hashed_password, specialization))
                        conn.commit()
                flash('Expert added successfully', 'success')
                return redirect(url_for('backend.dashboard'))
            except sqlite3.IntegrityError:
                flash('Email already registered', 'danger')
                return render_template('add-expert.html', admin=admin)
            except sqlite3.OperationalError as e:
                logger.error(f"Database operational error in add-expert: {e}")
                flash('Database is temporarily unavailable. Please try again.', 'danger')
                return render_template('add-expert.html', admin=admin)
            except sqlite3.Error as e:
                logger.error(f"Database error in add-expert: {e}")
                flash(f'Database error: {str(e)}', 'danger')
                return render_template('add-expert.html', admin=admin)
        return render_template('add-expert.html', admin=admin)
    except sqlite3.OperationalError as e:
        logger.error(f"Database operational error in add-expert: {e}")
        flash('Database is temporarily unavailable. Please try again.', 'danger')
        return redirect(url_for('backend.dashboard'))
    except sqlite3.Error as e:
        logger.error(f"Database error in add-expert: {e}")
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('backend.dashboard'))

@backend_bp.route('/edit-expert/<int:id>', methods=['GET', 'POST'])
def edit_expert(id):
    if 'username' not in session:
        logger.warning("No username in session for edit-expert, redirecting to login")
        flash('Please log in to access this page', 'danger')
        return redirect(url_for('backend.login'))
    try:
        with get_admin_db_connection() as conn:
            admin = conn.execute('SELECT * FROM admins WHERE username = ?', (session['username'],)).fetchone()
        if not admin:
            logger.warning(f"No admin found for username: {session['username']}")
            flash('Admin not found', 'danger')
            return redirect(url_for('backend.login'))
        with get_expert_db_connection() as conn:
            expert = conn.execute('SELECT * FROM experts WHERE id = ?', (id,)).fetchone()
        if not expert:
            logger.warning(f"No expert found for id: {id}")
            flash('Expert not found', 'danger')
            return redirect(url_for('backend.dashboard'))
        if request.method == 'POST':
            name = request.form.get('name')
            email = request.form.get('email')
            password = request.form.get('password')
            specialization = request.form.get('specialization')
            if not name or not email or not specialization:
                flash('Name, email, and specialization are required', 'danger')
                return render_template('edit-expert.html', expert=expert, admin=admin)
            try:
                with expert_db_lock:
                    with get_expert_db_connection() as conn:
                        c = conn.cursor()
                        if password:
                            if len(password) < 6:
                                flash('Password must be at least 6 characters', 'danger')
                                return render_template('edit-expert.html', expert=expert, admin=admin)
                            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
                            c.execute('UPDATE experts SET name = ?, email = ?, password = ?, specialization = ? WHERE id = ?',
                                      (name, email, hashed_password, specialization, id))
                        else:
                            c.execute('UPDATE experts SET name = ?, email = ?, specialization = ? WHERE id = ?',
                                      (name, email, specialization, id))
                        conn.commit()
                flash('Expert updated successfully', 'success')
                return redirect(url_for('backend.dashboard'))
            except sqlite3.IntegrityError:
                flash('Email already registered', 'danger')
                return render_template('edit-expert.html', expert=expert, admin=admin)
            except sqlite3.OperationalError as e:
                logger.error(f"Database operational error in edit-expert: {e}")
                flash('Database is temporarily unavailable. Please try again.', 'danger')
                return render_template('edit-expert.html', expert=expert, admin=admin)
            except sqlite3.Error as e:
                logger.error(f"Database error in edit-expert: {e}")
                flash(f'Database error: {str(e)}', 'danger')
                return render_template('edit-expert.html', expert=expert, admin=admin)
        return render_template('edit-expert.html', expert=expert, admin=admin)
    except sqlite3.OperationalError as e:
        logger.error(f"Database operational error in edit-expert: {e}")
        flash('Database is temporarily unavailable. Please try again.', 'danger')
        return redirect(url_for('backend.dashboard'))
    except sqlite3.Error as e:
        logger.error(f"Database error in edit-expert: {e}")
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('backend.dashboard'))

@backend_bp.route('/delete-expert/<int:id>', methods=['POST'])
def delete_expert(id):
    if 'username' not in session:
        logger.warning("No username in session for delete-expert, redirecting to login")
        flash('Please log in to access this page', 'danger')
        return redirect(url_for('backend.login'))
    try:
        with expert_db_lock:
            with get_expert_db_connection() as conn:
                c = conn.cursor()
                c.execute('DELETE FROM experts WHERE id = ?', (id,))
                conn.commit()
        flash('Expert deleted successfully', 'success')
    except sqlite3.OperationalError as e:
        logger.error(f"Database operational error in delete-expert: {e}")
        flash('Database is temporarily unavailable. Please try again.', 'danger')
    except sqlite3.Error as e:
        logger.error(f"Database error in delete-expert: {e}")
        flash(f'Database error: {str(e)}', 'danger')
    return redirect(url_for('backend.dashboard'))

@backend_bp.route('/expert-management')
def expert_management():
    if 'username' not in session:
        logger.warning("No username in session for expert-management, redirecting to login")
        flash('Please log in to access this page', 'danger')
        return redirect(url_for('backend.login'))
    try:
        with get_admin_db_connection() as conn:
            admin = conn.execute('SELECT * FROM admins WHERE username = ?', (session['username'],)).fetchone()
        if not admin:
            logger.warning(f"No admin found for username: {session['username']}")
            flash('Admin not found', 'danger')
            return redirect(url_for('backend.login'))
        with get_expert_db_connection() as conn:
            experts = conn.execute('SELECT id, name, email, specialization, created_at FROM experts').fetchall()
        return render_template('expert-management.html', experts=experts, admin=admin)
    except sqlite3.OperationalError as e:
        logger.error(f"Database operational error in expert-management: {e}")
        flash('Database is temporarily unavailable. Please try again.', 'danger')
        return redirect(url_for('backend.dashboard'))
    except sqlite3.Error as e:
        logger.error(f"Database error in expert-management: {e}")
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('backend.dashboard'))

@backend_bp.route('/add-user', methods=['GET', 'POST'])
def add_user():
    if 'username' not in session:
        logger.warning("No username in session for add-user, redirecting to login")
        flash('Please log in to access this page', 'danger')
        return redirect(url_for('backend.login'))
    try:
        with get_admin_db_connection() as conn:
            admin = conn.execute('SELECT * FROM admins WHERE username = ?', (session['username'],)).fetchone()
        if not admin:
            logger.warning(f"No admin found for username: {session['username']}")
            flash('Admin not found', 'danger')
            return redirect(url_for('backend.login'))
        if request.method == 'POST':
            name = request.form.get('name')
            email = request.form.get('email')
            password = request.form.get('password')
            if not name or not email or not password:
                flash('All fields are required', 'danger')
                return render_template('add-user.html', admin=admin)
            if len(password) < 6:
                flash('Password must be at least 6 characters', 'danger')
                return render_template('add-user.html', admin=admin)
            try:
                with user_db_lock:
                    with get_user_db_connection() as conn:
                        c = conn.cursor()
                        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
                        c.execute('INSERT INTO users (name, email, password, last_active) VALUES (?, ?, ?, ?)',
                                  (name, email, hashed_password, datetime.datetime.utcnow()))
                        conn.commit()
                flash('User added successfully', 'success')
                return redirect(url_for('backend.dashboard'))
            except sqlite3.IntegrityError:
                flash('Email already registered', 'danger')
                return render_template('add-user.html', admin=admin)
            except sqlite3.OperationalError as e:
                logger.error(f"Database operational error in add-user: {e}")
                flash('Database is temporarily unavailable. Please try again.', 'danger')
                return render_template('add-user.html', admin=admin)
            except sqlite3.Error as e:
                logger.error(f"Database error in add-user: {e}")
                flash(f'Database error: {str(e)}', 'danger')
                return render_template('add-user.html', admin=admin)
        return render_template('add-user.html', admin=admin)
    except sqlite3.OperationalError as e:
        logger.error(f"Database operational error in add-user: {e}")
        flash('Database is temporarily unavailable. Please try again.', 'danger')
        return redirect(url_for('backend.dashboard'))
    except sqlite3.Error as e:
        logger.error(f"Database error in add-user: {e}")
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('backend.dashboard'))

@backend_bp.route('/edit-user/<int:id>', methods=['GET', 'POST'])
def edit_user(id):
    if 'username' not in session:
        logger.warning("No username in session for edit-user, redirecting to login")
        flash('Please log in to access this page', 'danger')
        return redirect(url_for('backend.login'))
    try:
        with get_admin_db_connection() as conn:
            admin = conn.execute('SELECT * FROM admins WHERE username = ?', (session['username'],)).fetchone()
        if not admin:
            logger.warning(f"No admin found for username: {session['username']}")
            flash('Admin not found', 'danger')
            return redirect(url_for('backend.login'))
        with get_user_db_connection() as conn:
            user = conn.execute('SELECT * FROM users WHERE id = ?', (id,)).fetchone()
        if not user:
            logger.warning(f"No user found for id: {id}")
            flash('User not found', 'danger')
            return redirect(url_for('backend.dashboard'))
        if request.method == 'POST':
            name = request.form.get('name')
            email = request.form.get('email')
            password = request.form.get('password')
            if not name or not email:
                flash('Name and email are required', 'danger')
                return render_template('edit-user.html', user=user, admin=admin)
            try:
                with user_db_lock:
                    with get_user_db_connection() as conn:
                        c = conn.cursor()
                        if password:
                            if len(password) < 6:
                                flash('Password must be at least 6 characters', 'danger')
                                return render_template('edit-user.html', user=user, admin=admin)
                            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
                            c.execute('UPDATE users SET name = ?, email = ?, password = ? WHERE id = ?',
                                      (name, email, hashed_password, id))
                        else:
                            c.execute('UPDATE users SET name = ?, email = ? WHERE id = ?',
                                      (name, email, id))
                        conn.commit()
                flash('User updated successfully', 'success')
                return redirect(url_for('backend.dashboard'))
            except sqlite3.IntegrityError:
                flash('Email already registered', 'danger')
                return render_template('edit-user.html', user=user, admin=admin)
            except sqlite3.OperationalError as e:
                logger.error(f"Database operational error in edit-user: {e}")
                flash('Database is temporarily unavailable. Please try again.', 'danger')
                return render_template('edit-user.html', user=user, admin=admin)
            except sqlite3.Error as e:
                logger.error(f"Database error in edit-user: {e}")
                flash(f'Database error: {str(e)}', 'danger')
                return render_template('edit-user.html', user=user, admin=admin)
        return render_template('edit-user.html', user=user, admin=admin)
    except sqlite3.OperationalError as e:
        logger.error(f"Database operational error in edit-user: {e}")
        flash('Database is temporarily unavailable. Please try again.', 'danger')
        return redirect(url_for('backend.dashboard'))
    except sqlite3.Error as e:
        logger.error(f"Database error in edit-user: {e}")
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('backend.dashboard'))

@backend_bp.route('/delete-user/<int:id>', methods=['POST'])
def delete_user(id):
    if 'username' not in session:
        logger.warning("No username in session for delete-user, redirecting to login")
        flash('Please log in to access this page', 'danger')
        return redirect(url_for('backend.login'))
    try:
        with user_db_lock:
            with get_user_db_connection() as conn:
                c = conn.cursor()
                c.execute('DELETE FROM users WHERE id = ?', (id,))
                conn.commit()
        flash('User deleted successfully', 'success')
    except sqlite3.OperationalError as e:
        logger.error(f"Database operational error in delete-user: {e}")
        flash('Database is temporarily unavailable. Please try again.', 'danger')
    except sqlite3.Error as e:
        logger.error(f"Database error in delete-user: {e}")
        flash(f'Database error: {str(e)}', 'danger')
    return redirect(url_for('backend.dashboard'))

@backend_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            error_message = 'Username and password are required'
            if is_ajax:
                return jsonify({'success': False, 'message': error_message}), 400
            flash(error_message, 'danger')
            return render_template('login.html')
        try:
            with get_admin_db_connection() as conn:
                user = conn.execute('SELECT * FROM admins WHERE username = ?', (username,)).fetchone()
            if user and check_password_hash(user['password'], password):
                session['username'] = username
                session['user_id'] = user['id']
                logger.info(f"Admin logged in: {username}")
                if is_ajax:
                    return jsonify({
                        'success': True,
                        'message': 'Login successful!',
                        'redirect': url_for('backend.dashboard')
                    })
                flash('Login successful!', 'success')
                return redirect(url_for('backend.dashboard'))
            else:
                error_message = 'Invalid username or password'
                logger.warning(f"Failed login attempt for username: {username}")
                if is_ajax:
                    return jsonify({'success': False, 'message': error_message}), 401
                flash(error_message, 'danger')
                return render_template('login.html')
        except sqlite3.OperationalError as e:
            logger.error(f"Database operational error during admin login: {e}")
            error_message = 'Database is temporarily unavailable. Please try again.'
            if is_ajax:
                return jsonify({'success': False, 'message': error_message}), 503
            flash(error_message, 'danger')
            return render_template('login.html')
        except sqlite3.Error as e:
            logger.error(f"Database error during admin login: {e}")
            error_message = f'Database error: {str(e)}'
            if is_ajax:
                return jsonify({'success': False, 'message': error_message}), 500
            flash(error_message, 'danger')
            return render_template('login.html')
    return render_template('login.html')

@backend_bp.route('/logout')
def logout():
    username = session.get('username', 'unknown')
    session.pop('username', None)
    session.pop('user_id', None)
    logger.info(f"Admin logged out: {username}")
    flash('You have been logged out', 'info')
    return redirect(url_for('backend.login'))

@backend_bp.route('/lockscreen')
def lockscreen():
    return render_template('authentication-lockscreen.html')

@backend_bp.route('/authentication/recoverpw')
def recoverpw():
    return render_template('authentication-recoverpw.html')

@backend_bp.route('/error/400')
def error_400():
    return render_template('error-400.html')

@backend_bp.route('/error/403')
def error_403():
    return render_template('error-403.html')

@backend_bp.route('/error/404')
def error_404():
    return render_template('error-404.html')

@backend_bp.route('/error/500')
def error_500():
    return render_template('error-500.html')

@backend_bp.route('/error/503')
def error_503():
    return render_template('error-503.html')

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