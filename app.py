import os
import bleach
from flask import Flask, render_template, redirect, url_for, flash, session, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from forms import LoginForm, RegisterForm, ContactForm
from models import db, User, Contact

# ─────────────────────────────────────────────
# App Configuration
# ─────────────────────────────────────────────
app = Flask(__name__)

# Secret key for session & CSRF
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-this-in-production-use-env-var')

# Database (SQLAlchemy ORM — parameterized queries by default)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ── SECURITY PRACTICE 3: Secure Session / Cookie Settings ──────────────────
app.config['SESSION_COOKIE_HTTPONLY'] = True   # Block JS access to cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF mitigation
# app.config['SESSION_COOKIE_SECURE'] = True   # Enable when using HTTPS

# ── SECURITY PRACTICE 3: CSRF Protection via Flask-WTF ─────────────────────
csrf = CSRFProtect(app)

# ── SECURITY PRACTICE 5: Password Hashing via Bcrypt ───────────────────────
bcrypt = Bcrypt(app)

db.init_app(app)

with app.app_context():
    db.create_all()


# ─────────────────────────────────────────────
# Helper – sanitize any string (Practice 1 & 3)
# ─────────────────────────────────────────────
def sanitize(value):
    """Strip all HTML/script tags from a string using bleach."""
    return bleach.clean(value, tags=[], strip=True)


# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────

@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # ── PRACTICE 1: Input already validated by WTForms validators ──────
        username = sanitize(form.username.data)
        email    = sanitize(form.email.data)

        # Check duplicate
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('register.html', form=form)
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return render_template('register.html', form=form)

        # ── PRACTICE 5: Hash password with bcrypt before saving ────────────
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        # ── PRACTICE 2: ORM handles parameterized INSERT automatically ──────
        user = User(username=username, email=email, password=hashed_pw)
        db.session.add(user)
        db.session.commit()

        flash('Account created! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = sanitize(form.username.data)

        # ── PRACTICE 2: ORM query — parameterized, no raw SQL ───────────────
        user = User.query.filter_by(username=username).first()

        # ── PRACTICE 2 & 5: Check hashed password ───────────────────────────
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            session['user_id']  = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # ── PRACTICE 2: Generic error — never reveal which field failed ──
            flash('Invalid credentials. Please try again.', 'error')

    return render_template('login.html', form=form)


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))
    contacts = Contact.query.filter_by(user_id=session['user_id']).all()
    return render_template('dashboard.html', contacts=contacts)


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if 'user_id' not in session:
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))

    form = ContactForm()
    if form.validate_on_submit():
        # ── PRACTICE 1: Sanitize every field ────────────────────────────────
        name    = sanitize(form.name.data)
        email   = sanitize(form.email.data)
        phone   = sanitize(form.phone.data)
        website = sanitize(form.website.data) if form.website.data else ''
        message = sanitize(form.message.data)

        # ── PRACTICE 2: ORM INSERT — parameterized ───────────────────────────
        entry = Contact(
            name=name, email=email, phone=phone,
            website=website, message=message,
            user_id=session['user_id']
        )
        db.session.add(entry)
        db.session.commit()
        flash('Contact submitted successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('contact.html', form=form)


@app.route('/delete/<int:contact_id>', methods=['POST'])
def delete_contact(contact_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # ── PRACTICE 2: ORM handles parameterized DELETE ─────────────────────
    entry = Contact.query.filter_by(id=contact_id, user_id=session['user_id']).first_or_404()
    db.session.delete(entry)
    db.session.commit()
    flash('Contact deleted.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))


# ─────────────────────────────────────────────
# SECURITY PRACTICE 4: Custom Error Pages
# ─────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def server_error(e):
    return render_template('errors/500.html'), 500


@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403


if __name__ == '__main__':
    # Debug=False in production
    app.run(debug=False)
