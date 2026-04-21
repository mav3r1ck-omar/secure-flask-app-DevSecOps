from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = 'users'
    id       = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80),  nullable=False, unique=True)
    email    = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)   # stores bcrypt hash
    contacts = db.relationship('Contact', backref='owner', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'


class Contact(db.Model):
    __tablename__ = 'contacts'
    id      = db.Column(db.Integer, primary_key=True)
    name    = db.Column(db.String(100), nullable=False)
    email   = db.Column(db.String(120), nullable=False)
    phone   = db.Column(db.String(20),  nullable=True)
    website = db.Column(db.String(200), nullable=True)
    message = db.Column(db.Text,        nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __repr__(self):
        return f'<Contact {self.name}>'
