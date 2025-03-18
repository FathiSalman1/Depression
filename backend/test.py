from flask import Flask, Blueprint, render_template

# Create the Flask application
app = Flask(__name__)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  # SQLite database file
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key'  # Required for flashing messages

# Create a Blueprint for the backend
backend_bp = Blueprint('backend', __name__, template_folder='backend/templates')

# Backend Routes
@backend_bp.route('/dashboard')
def dashboard():
    return render_template('/dashboard.html')

@backend_bp.route('/add-expert')
def addexpert():
    return render_template('/add-expert.html')

@backend_bp.route('/login')
def login():
    return render_template('login.html')

@backend_bp.route('/lockscreen')
def lockscreen():
    return render_template('authentication-lockscreen.html')

@backend_bp.route('/authentication/recoverpw')
def recoverpw():
    return render_template('authentication-recoverpw.html')

# Error Handlers
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

# Create a Blueprint for the frontend
frontend_bp = Blueprint('frontend', __name__, template_folder='frontend/templates')

# Frontend Routes
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

# Register the Blueprints with the app
app.register_blueprint(backend_bp, url_prefix='/@dmin')
app.register_blueprint(frontend_bp)

# Run the Flask application
if __name__ == '__main__':
    app.run(debug=True)