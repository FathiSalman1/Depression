from flask import Blueprint, render_template

# Create the frontend Blueprint
frontend_bp = Blueprint('frontend', __name__, template_folder='templates')

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

@frontend_bp.route('/depression-test')
def depression_test():
    return render_template('depression-test.html')