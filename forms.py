import re
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField
from wtforms.validators import (DataRequired, Email, Length, Regexp,
                                Optional, ValidationError)


# ── Custom validator: reject obvious SQL injection keywords ─────────────────
def no_sql_injection(form, field):
    sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP',
                    'UNION', 'OR', 'AND', '--', ';', '/*', '*/']
    value = field.data.upper()
    for kw in sql_keywords:
        if kw in value:
            raise ValidationError('Input contains disallowed characters or keywords.')


# ── Custom validator: block script/HTML tags ─────────────────────────────────
def no_html_tags(form, field):
    if re.search(r'<[^>]+>', field.data):
        raise ValidationError('HTML tags are not allowed in this field.')


# ────────────────────────────────────────────────────────────────────────────
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message='Username is required.'),
        Length(min=3, max=80, message='Username must be 3–80 characters.'),
        Regexp(r'^[A-Za-z0-9_]+$',
               message='Username may only contain letters, numbers, and underscores.'),
    ])
    email = StringField('Email', validators=[
        DataRequired(message='Email is required.'),
        Email(message='Enter a valid email address.'),
        Length(max=120),
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message='Password is required.'),
        Length(min=8, message='Password must be at least 8 characters.'),
        Regexp(r'^(?=.*[A-Z])(?=.*\d)',
               message='Password must contain at least one uppercase letter and one number.'),
    ])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message='Username is required.'),
        Length(max=80),
        no_sql_injection,
        no_html_tags,
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message='Password is required.'),
    ])
    submit = SubmitField('Login')


class ContactForm(FlaskForm):
    name = StringField('Your Name', validators=[
        DataRequired(message='Name is required.'),
        Length(min=2, max=100, message='Name must be 2–100 characters.'),
        no_html_tags,
        no_sql_injection,
    ])
    email = StringField('Email Address', validators=[
        DataRequired(message='Email is required.'),
        Email(message='Enter a valid email address.'),
        Length(max=120),
    ])
    phone = StringField('Phone Number (optional)', validators=[
        Optional(),
        Regexp(r'^[\d\s\+\-\(\)]{7,20}$',
               message='Enter a valid phone number (digits, spaces, +, -, parentheses).'),
    ])
    website = StringField('Website (optional)', validators=[
        Optional(),
        Length(max=200),
        Regexp(r'^(https?://)?[\w\-]+(\.[\w\-]+)+(\/\S*)?$',
               message='Enter a valid website URL.'),
    ])
    message = TextAreaField('Message', validators=[
        DataRequired(message='Message is required.'),
        Length(min=5, max=2000, message='Message must be 5–2000 characters.'),
        no_html_tags,
        no_sql_injection,
    ])
    submit = SubmitField('Submit')
