from flask_sqlalchemy import SQLAlchemy

# Initialize the database
db = SQLAlchemy()

# Define a model (e.g., for storing user data)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"