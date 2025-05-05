# -----------------------------
# 📦 Imports and Configuration
# -----------------------------
from emails import build_sop_assignment_email
from urllib.parse import urlencode  # make sure this is at the top if not already
from sqlalchemy import func, or_
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import joinedload
from functools import wraps
from datetime import datetime
from flask import request
from math import ceil
import os
import re
import pandas as pd
from flask_mail import Mail, Message
from sqlalchemy import func, or_, extract
from markupsafe import Markup  
import json
from datetime import timedelta
from flask_migrate import Migrate
from functools import wraps  # <-- add this import
from flask_mail import Mail, Message
import secrets
from werkzeug.utils import secure_filename
from io import BytesIO
from flask import send_file
from flask import jsonify
from flask_wtf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string
from sqlalchemy import event
from sqlalchemy.engine import Engine
import sqlite3
from flask import Flask, render_template
from flask_login import LoginManager
from functools import wraps
from flask import session, redirect, url_for, flash
from weasyprint import HTML
from flask import make_response
import sys






# ✉️ Email Templates
from emails import (
    build_password_reset_email,
    build_welcome_email,
    build_sop_assignment_email,
    build_due_reminder_email,
    build_amendment_closed_email
)


ROLE_CHOICES = [
    'Admin',
    'Director',
    'Head of Department',
    'Research Officer',
    'Research Assistant',
    'National Service Personnel',
    'Guest',
    'Monitor',
    'Junior Staff'
]



# 🔧 Flask App Configuration
app = Flask(__name__)

# csrf = CSRFProtect(app)
app.secret_key = 'subz tpim wwog bbkn'  # 🔐 For session security
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sop_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ✉️ Setup Mail (use your actual SMTP settings here)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'williamdormechele@gmail.com'
app.config['MAIL_PASSWORD'] = 'subz tpim wwog bbkn'
app.config['MAIL_DEFAULT_SENDER'] = 'williamdormechele@gmail.com'

# 📁 File Upload Config
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx'}

# 🔗 Initialize SQLAlchemy
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
mail = Mail(app)

from functools import wraps
from flask import session, redirect, url_for, flash
from flask import abort
from flask_login import current_user



# 🔐 LOGIN REQUIRED DECORATOR
def login_required(role=None):
    def decorator(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if 'username' not in session:
                flash('You must be logged in to access this page.', 'error')
                return redirect(url_for('login'))
            if role:
                user_role = session.get('role')
                if isinstance(role, list):
                    if user_role not in role:
                        flash('Access denied: Insufficient permissions.', 'error')
                        return redirect(url_for('home'))
                elif user_role != role:
                    flash('Access denied: Insufficient permissions.', 'error')
                    return redirect(url_for('home'))
            return fn(*args, **kwargs)
        return decorated_view
    return decorator


def roles_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def validate_role(role):
    if role not in ROLE_CHOICES:
        raise ValueError(f"Invalid role: {role}")


def generate_random_password(length=10):
    """Generate a secure random password with letters, digits, and punctuation."""
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.SystemRandom().choice(characters)
                       for _ in range(length))
    return password


def is_strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[\W_]', password):  # special chars: !@#$% etc.
        return False
    return True

def send_amendment_email(subject, html_body, recipients):
    msg = Message(
        subject, sender=app.config['MAIL_USERNAME'], recipients=recipients)
    msg.html = html_body   # <-- Use HTML content
    mail.send(msg)

@event.listens_for(Engine, "connect")
def enable_sqlite_foreign_key_constraint(dbapi_connection, connection_record):
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.close()

# ✅ Allowed file extensions for uploads
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/user-manual')
@login_required()
def user_manual():
    return render_template('user_manual.html')


@app.route('/api-docs')
@login_required()
def api_docs():
    return render_template('api_docs.html')


@app.route('/faq')
@login_required()
def faq():
    return render_template('faq.html')


# Initialize Flask-Mail
# ✉️ Unified Send Email Function
@app.route('/send_reply/<int:ticket_id>', methods=['POST'])
@login_required(role='Admin')
def send_reply(ticket_id):
    ticket = SupportTicket.query.get_or_404(ticket_id)
    reply_message = request.form.get('reply_message')

    if not reply_message:
        flash("Reply message cannot be empty.", "error")
        return redirect(url_for('reply_ticket_page', ticket_id=ticket_id))

    ticket.reply_message = reply_message
    ticket.status = 'Closed'
    db.session.commit()

    # ✅ FIX: use html_body instead of body
    send_email(
        to_email=ticket.email,
        subject=f"Reply to your Ticket: {ticket.subject}",
        html_body = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="UTF-8">
        <title>Reply to Your Ticket</title>
        <style>
        body {{
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            margin: 0; padding: 0;
        }}
        .container {{
            max-width: 600px;
            margin: 40px auto;
            background: #ffffff;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            padding-bottom: 20px;
            border-bottom: 1px solid #dddddd;
        }}
        .title {{
            color: #0044cc;
            margin: 0;
        }}
        .content {{
            padding: 20px 0;
            color: #333333;
            font-size: 16px;
        }}
        .footer {{
            margin-top: 30px;
            font-size: 12px;
            text-align: center;
            color: #888888;
            border-top: 1px solid #dddddd;
            padding-top: 15px;
        }}
        </style>
        </head>
        <body>
        <div class="container">
        <div class="header">
            <h2 class="title">Re: {ticket.subject}</h2>
        </div>
        <div class="content">
            <p>Dear <strong>{ticket.name}</strong>,</p>
            <p><strong>Re:</strong> {reply_message}</p>
            <p>If you have further questions, feel free to reply to this email.</p>
        </div>
        <div class="footer">
            Best regards,<br>
            <strong>NHRC SOP Portal Support Team</strong><br>
            © 2025 NHRC SOP Portal
        </div>
        </div>
        </body>
        </html>
        """
)

    flash("Reply sent successfully.", "success")
    return redirect(url_for('support_tickets'))



# -----------------------------
# 🗃️ Database Models
# -----------------------------
# 👤 User table


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)  # rename field!
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False)
    fullname = db.Column(db.String(100))
    is_blocked = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    must_change = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)




# 📄 SOP Model with Amendments
class SOP(db.Model):
    __tablename__ = 'sop'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    base_filename = db.Column(db.String(200))  # Used for version tracking
    category = db.Column(db.String(50))
    subcategory = db.Column(db.String(50))
    uploaded_by = db.Column(db.String(100))
    date_uploaded = db.Column(db.DateTime, default=datetime.utcnow)
    version = db.Column(db.String(10), default='1.0')
    status = db.Column(db.String(20), default='draft')  # 'draft' or 'approved'
    approved_by = db.Column(db.String(100))
    date_approved = db.Column(db.DateTime)
    
    deleted = db.Column(db.Boolean, default=False)

    audit_logs = db.relationship(
        'AuditLog', backref='sop', cascade="all, delete-orphan")
    read_logs = db.relationship(
        'ReadLog', backref='sop', cascade="all, delete-orphan")

    # Relationships
    read_logs = db.relationship(
        'ReadLog', backref='sop', cascade="all, delete-orphan")
    audit_logs = db.relationship(
        'AuditLog', backref='sop', cascade="all, delete-orphan")
    


# 📚 Read Log Model
# 📌 Read log table – tracks who read what and when
class ReadLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sop_id = db.Column(db.Integer, db.ForeignKey('sop.id'), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    date_read = db.Column(db.DateTime, default=datetime.utcnow)
    
    
# 📝 Audit Log Model
class AuditLog(db.Model):
    __tablename__ = 'audit_log'
    id = db.Column(db.Integer, primary_key=True)
    sop_id = db.Column(db.Integer, db.ForeignKey('sop.id'))
    sop_filename = db.Column(db.String(200))  # ✅ must be here!
    username = db.Column(db.String(100))
    action = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)

# SOP Assignment Table
class SOPAssignment(db.Model):
    __tablename__ = 'sop_assignment'
    id = db.Column(db.Integer, primary_key=True)
    sop_id = db.Column(db.Integer, db.ForeignKey('sop.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    acknowledged = db.Column(db.Boolean, default=False)
    date_read = db.Column(db.DateTime)
    date_assigned = db.Column(db.DateTime, default=datetime.utcnow)
    assigned_by = db.Column(db.String(100))

    sop = db.relationship('SOP', backref='assignments')
    user = db.relationship('User', backref=db.backref(
        'assignments', cascade='all, delete-orphan'))




# 📑 Amendment Model
class Amendment(db.Model):
    __tablename__ = 'amendment'
    id = db.Column(db.Integer, primary_key=True)
    sop_id = db.Column(db.Integer, db.ForeignKey('sop.id'), nullable=False)
    raised_by = db.Column(db.String(100), nullable=False)
    date_raised = db.Column(db.DateTime, default=datetime.utcnow)
    sop_section = db.Column(db.String(200))
    details = db.Column(db.Text)
    suggestion = db.Column(db.Text)
    severity = db.Column(db.String(20))
    sop_version = db.Column(db.String(10))
    owner = db.Column(db.String(100))  # auto-populated from SOP
    status = db.Column(db.String(10), default='draft')  # 'draft' or 'final'
    age = db.Column(db.Integer, default=0)  # System calculated

    # Stage 2 fields
    updated_by = db.Column(db.String(100))
    update_date = db.Column(db.DateTime)
    update_details = db.Column(db.Text)
    consensus_reached = db.Column(db.Boolean, default=False)
    closed_by = db.Column(db.String(100))
    closed_date = db.Column(db.DateTime)
    new_version = db.Column(db.String(10))
    is_closed = db.Column(db.Boolean, default=False)

    sop = db.relationship('SOP', backref='amendments')


# 🧾 Amendment Audit Log Model
class AmendmentAudit(db.Model):
    __tablename__ = 'amendment_audit_log'
    id = db.Column(db.Integer, primary_key=True)
    amendment_id = db.Column(db.Integer, db.ForeignKey(
        'amendment.id'), nullable=False)
    username = db.Column(db.String(100))
    action = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)

    amendment = db.relationship('Amendment', backref='audit_trail')


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    title = db.Column(db.String(255))
    message = db.Column(db.Text)
    seen = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='notifications')


class APIKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    description = db.Column(db.String(255))
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    created_by = db.Column(db.String(80))


class Setting(db.Model):
    __tablename__ = 'setting'
    __table_args__ = {'extend_existing': True}  # 🛠 Important
    
    id = db.Column(db.Integer, primary_key=True)
    portal_name = db.Column(db.String(150), default='NHRC SOP Portal')
    admin_email = db.Column(db.String(150), default='williamdormechele@gmail.com')
    logo_filename = db.Column(db.String(150), nullable=True)
    theme_color = db.Column(db.String(50), default='Blue')
    enable_registration = db.Column(db.Boolean, default=True)


class SupportTicket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.String(20), unique=True, nullable=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), nullable=False)
    subject = db.Column(db.String(255), nullable=False)  # <-- Add this line
    message = db.Column(db.Text, nullable=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default="Open")
    reply_message = db.Column(db.Text, nullable=True)


# -----------------------------
# 🔐 Login Decorator
# -----------------------------
# ✅ Admin only shortcut
def admin_required(fn):
    return login_required(role='Admin')(fn)


# 🔒 ADMIN REQUIRED DECORATOR (Shortcut)
def admin_required(fn):
    return login_required(role='Admin')(fn)

def get_role_counts():
    role_labels = [
        'Admin', 'Director', 'Head of Department', 'Research Officer',
        'Research Assistant', 'National Service Personnel', 'Guest',
        'Monitor', 'Junior Staff'
    ]
    role_counts = []
    for role in role_labels:
        count = User.query.filter_by(role=role).count()
        role_counts.append(count)
    return role_labels, role_counts


# Admin Required Decorator
# def admin_required(f):
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if 'role' not in session or session['role'] != 'Admin':
#             flash('Admin access required.', 'error')
#             return redirect(url_for('home'))
#         return f(*args, **kwargs)
#     return decorated_function


@app.context_processor
def inject_settings():
    settings = Setting.query.first()
    return dict(settings=settings)



# -----------------------------
# 🌍 Routes (Public Pages)
# -----------------------------
@app.route('/')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

# -----------------------------
# 👤 User Authentication
# -----------------------------

# 🔐 Register new user
@app.route('/register', methods=['GET', 'POST'])
@login_required(role='Admin')  # Only admins can access
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        role = request.form['role']
        fullname = request.form['fullname']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'error')
            return redirect(url_for('register'))

        # 🔥 Generate random password
        random_password = generate_random_password()
        while not is_strong_password(random_password):
            random_password = generate_random_password()
        hashed_password = generate_password_hash(random_password)

        
        # 🔥 Create user with hashed password
        user = User(
            fullname=fullname,
            username=username,
            email=email,
            password_hash=hashed_password,
            role=role,
            must_change=True
        )
        db.session.add(user)
        db.session.commit()

        # 🔥 Send email with temporary password
        html_body = build_welcome_email(user, random_password)

        send_email(
            email,
            "💼 Welcome to NHRC SOP Portal",
            html_body
        )

        flash('✅ User account created! Login details sent by email.', 'success')
        return redirect(url_for('admin_manage_users'))

    return render_template('register.html')



# 🔑 Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        # if user and check_password(user.password, password):
        if user and user.check_password(password):
            session['username'] = user.username
            session['role'] = user.role

            # ✅ Log login to AuditLog (placed BEFORE redirect)
            db.session.add(AuditLog(
                sop_filename=None,
                username=user.username,
                action='login',
                notes='User logged in'
            ))
            db.session.commit()

            if user.must_change:
                flash('Please change your default password.', 'warning')
                return redirect(url_for('change_password'))

            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials', 'error')

    return render_template('login.html')



# 🔓 Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# 🔁 Change password
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['username']).first()

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if not new_password or not confirm_password:
            flash('Please fill in all fields.', 'error')
            return redirect(url_for('change_password'))

        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return redirect(url_for('change_password'))

        if not is_strong_password(new_password):
            flash('Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.', 'error')
            return redirect(url_for('change_password'))


        # Update password
        user.password_hash = generate_password_hash(new_password)
        user.must_change = False  # Clear the must_change flag
        db.session.commit()

        flash('Password changed successfully. Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('change_password.html')


# 🔑 Forgot password (validate identity)
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        user = User.query.filter_by(username=username, email=email).first()
        if user:
            session['reset_user'] = user.username
            return redirect(url_for('reset_password'))
        else:
            flash('Username and email do not match.', 'error')
    return render_template('forgot_password.html')


# 🔄 Reset password
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_user' not in session:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('login'))
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm = request.form['confirm_password']
        if new_password != confirm:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('reset_password'))
        
        if not is_strong_password(new_password):
            flash('Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.', 'error')
            return redirect(url_for('reset_password'))

        user = User.query.filter_by(username=session.pop('reset_user')).first()
        user.password_hash = generate_password_hash(new_password)
        user.must_change = False
        db.session.commit()
        flash('Password reset successful. You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html')


# -----------------------------
# 🆙 Upload SOP (admin only)
# -----------------------------
@app.route('/upload', methods=['GET', 'POST'])
@login_required(role=['Admin', 'Director', 'Head of Department'])
def upload_file():
    if request.method == 'POST':
        files = request.files.getlist('files')
        category = request.form.get('category')
        subcategory = request.form.get('subcategory')
        messages = []

        for file in files:
            if file and allowed_file(file.filename):
                filename = file.filename
                base_name = os.path.splitext(filename)[0]
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)

                # Auto-increment version
                latest = SOP.query.filter_by(base_filename=base_name).order_by(
                    SOP.date_uploaded.desc()).first()
                new_version = str(
                    round(float(latest.version) + 0.1, 1)) if latest else "1.0"

                sop = SOP(
                    filename=filename,
                    base_filename=base_name,
                    category=category,
                    subcategory=subcategory,
                    uploaded_by=session['username'],
                    version=new_version,
                    status='draft'
                )
                db.session.add(sop)
                audit = AuditLog(
                    sop=sop,
                    sop_filename=sop.filename,
                    action="uploaded",
                    username=session['username'],
                    notes=f"Uploaded version {new_version}"
                )
                db.session.add(audit)
                messages.append(f"{filename} as version {new_version}")
            else:
                messages.append(f"{file.filename} skipped (invalid format)")

        db.session.commit()
        flash(" | ".join(messages), "success")
        return redirect(url_for('list_sops'))

    return render_template('upload.html')



# 📄 View SOP Documents (Upgraded)
@app.route('/documents')
@login_required()
def documents_page():
    query = SOP.query.filter_by(deleted=False)

    # 🏷️ Get query params
    status = request.args.get('status')
    keywords = request.args.get('keywords')
    content = request.args.get('content')
    owner = request.args.get('owner')
    approver = request.args.get('approver')
    copy_holder = request.args.get('copy_holder')
    category = request.args.get('category')
    uploaded = request.args.get('uploaded')

    # 🛠️ Apply filters
    if status:
        if status.lower() == 'draft':
            query = query.filter(SOP.status == 'draft')
        elif status.lower() == 'final':
            query = query.filter(SOP.status == 'approved')
        else:
            query = query.filter(SOP.status.ilike(status))

    if owner:
        query = query.filter(SOP.uploaded_by.ilike(f"%{owner}%"))

    if approver:
        query = query.filter(SOP.approved_by.ilike(f"%{approver}%"))

    if copy_holder:
        query = query.filter(SOP.uploaded_by.ilike(f"%{copy_holder}%"))

    if category:
        query = query.filter(SOP.category == category)

    if uploaded:
        try:
            year, month = map(int, uploaded.split('-'))
            query = query.filter(
                db.extract('year', SOP.date_uploaded) == year,
                db.extract('month', SOP.date_uploaded) == month
            )
        except ValueError:
            pass  # Ignore bad format

    # 🔍 Keywords and content search
    if keywords:
        keyword_pattern = f"%{keywords}%"
        query = query.filter(or_(
            SOP.filename.ilike(keyword_pattern),
            SOP.category.ilike(keyword_pattern),
            SOP.subcategory.ilike(keyword_pattern)
        ))

    if content:
        query = query.filter(SOP.filename.ilike(f"%{content}%"))

    # 📄 Results
    results = query.order_by(SOP.date_uploaded.desc()).all()
    
    # 🆕 Get draft SOPs
    draft_sops = SOP.query.filter_by(status='draft', deleted=False).all()

    # 🆕 Populate dropdown options
    status_options = [s[0] for s in db.session.query(
        SOP.status).filter(SOP.status.isnot(None)).distinct()]
    owner_options = [o[0] for o in db.session.query(
        SOP.uploaded_by).filter(SOP.uploaded_by.isnot(None)).distinct()]
    approver_options = [a[0] for a in db.session.query(
        SOP.approved_by).filter(SOP.approved_by.isnot(None)).distinct()]
    copy_holders = owner_options

    # 📅 Pass current time (optional)
    from datetime import datetime
    now = datetime.utcnow()

    return render_template(
        'documents.html',
        results=results,
        status_options=status_options,
        owner_options=owner_options,
        approver_options=approver_options,
        copy_holders=copy_holders,
        now=now, 
        draft_sops=draft_sops  # ✅ Pass draft_sops!
    )


# 📄 Approve Draft SOPs
@app.route('/approve/<int:sop_id>')
@login_required()
def approve_sop(sop_id):
    if session['role'] not in ['Admin', 'Director', 'Head of Department']:
        return "Unauthorized", 403

    sop = SOP.query.get_or_404(sop_id)
    if sop.status == 'approved':
        flash('SOP is already approved.', 'info')
        return redirect(url_for('list_sops'))

    sop.status = 'approved'
    sop.date_approved = datetime.utcnow()
    sop.approved_by = session['username']

    # Log to audit
    audit = AuditLog(
        sop=sop,
        sop_filename=sop.filename,
        action="approved",
        username=session['username'],
        notes=f"Approved version {sop.version}"
    )
    db.session.add(audit)
    db.session.commit()

    flash(f"{sop.filename} approved successfully!", "success")
    return redirect(url_for('list_sops'))


# Delete
@app.route('/delete/<int:sop_id>', methods=['POST'])
@login_required()
def delete_sop(sop_id):
    if session.get('role') not in ['Admin', 'Director', 'Head of Department']:
        flash("You are not authorized to perform this action.", "error")
        return redirect(url_for('list_sops'))

    sop = SOP.query.get_or_404(sop_id)
    sop.deleted = True  # soft delete
    db.session.add(AuditLog(
        sop_filename=sop.filename,
        username=session['username'],
        action='deleted',
        notes=f"Deleted SOP {sop.filename} (version {sop.version})"
    ))
    db.session.commit()
    flash(f"{sop.filename} marked as deleted.", "success")
    return redirect(url_for('list_sops'))


# View Version History
@app.route('/version-history/<filename>')
@login_required()
def version_history(filename):
    versions = SOP.query.filter_by(
        filename=filename).order_by(SOP.version.desc()).all()
    current_version = versions[0].version if versions else None
    return render_template('version_history.html', versions=versions, filename=filename, current_version=current_version, active_page='sops')


# Restore Older Version Button
@app.route('/restore/<int:sop_id>', methods=['POST'])
@login_required(role=['Admin', 'Director', 'Head of Department'])
def restore_sop(sop_id):
    sop = SOP.query.get_or_404(sop_id)
    sop.deleted = False
    db.session.add(AuditLog(
        sop_filename=sop.filename,
        username=session['username'],
        action='restored',
        notes=f"Restored SOP {sop.filename} (version {sop.version})"
    ))
    db.session.commit()
    flash(f"{sop.filename} restored.", "success")
    return redirect(url_for('audit_log'))


# 📄 View/filter SOPs
@app.route('/sops')
@login_required()
def list_sops():
    query = SOP.query.filter_by(deleted=False).options(
        joinedload(SOP.read_logs))

    # Fetch dropdown options
    status_options = [s[0] for s in db.session.query(
        SOP.status).distinct().all() if s[0]]
    owner_options = [u[0] for u in db.session.query(
        SOP.uploaded_by).distinct().all() if u[0]]
    approver_options = [a[0] for a in db.session.query(
        SOP.approved_by).distinct().all() if a[0]]
    copy_holders = owner_options

    # Filters
    selected_category = request.args.get('category')
    if selected_category and selected_category != "All":
        query = query.filter_by(category=selected_category)

    search_query = request.args.get('search')
    if search_query:
        query = query.filter(SOP.filename.ilike(f"%{search_query}%"))

    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    if start_date:
        try:
            start = datetime.strptime(start_date, "%Y-%m-%d")
            query = query.filter(SOP.date_uploaded >= start)
        except ValueError:
            flash("Invalid start date format. Use YYYY-MM-DD", "error")

    if end_date:
        try:
            end = datetime.strptime(end_date, "%Y-%m-%d")
            query = query.filter(SOP.date_uploaded <= end)
        except ValueError:
            flash("Invalid end date format. Use YYYY-MM-DD", "error")

    status = request.args.get('status')
    if status:
        query = query.filter(SOP.status == status)

    owner = request.args.get('owner')
    if owner:
        query = query.filter(SOP.uploaded_by == owner)

    approver = request.args.get('approver')
    if approver:
        query = query.filter(SOP.approved_by == approver)

    keywords = request.args.get('keywords')
    if keywords:
        keyword_pattern = f"%{keywords}%"
        query = query.filter(
            SOP.filename.ilike(keyword_pattern) |
            SOP.category.ilike(keyword_pattern) |
            SOP.subcategory.ilike(keyword_pattern)
        )

    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = 10
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    files = pagination.items

    # ✅ Proper base_query_string setup
    args = request.args.to_dict()  # 👈 ADD this line
    args.pop('page', None)          # 👈 Remove page parameter if exists
    base_query_string = urlencode(args)  # 👈 Now you can urlencode safely

    categories = [c[0] for c in db.session.query(
        SOP.category).distinct().all() if c[0]]

    return render_template(
        "sops.html",
        files=files,
        pagination=pagination,
        categories=categories,
        selected_category=selected_category,
        search_query=search_query,
        start_date=start_date,
        end_date=end_date,
        status_options=status_options,
        owner_options=owner_options,
        approver_options=approver_options,
        copy_holders=copy_holders,
        base_query_string=base_query_string  # 👈 Now passed correctly
    )



# Audit Log
@app.route('/audit-log')
@login_required(role=['Admin', 'Director', 'Head of Department'])
def audit_log():
    query = AuditLog.query.order_by(AuditLog.timestamp.desc())

    # Filters
    username = request.args.get('user')
    action = request.args.get('action')
    start = request.args.get('start_date')
    end = request.args.get('end_date')

    if username:
        query = query.filter_by(username=username)
    if action:
        query = query.filter_by(action=action)
    if start:
        query = query.filter(AuditLog.timestamp >=
                             datetime.strptime(start, '%Y-%m-%d'))
    if end:
        query = query.filter(AuditLog.timestamp <=
                             datetime.strptime(end, '%Y-%m-%d'))

    logs = query.all()
    users = db.session.query(AuditLog.username).distinct()
    actions = db.session.query(AuditLog.action).distinct()

    return render_template('audit_log.html', logs=logs, users=users, actions=actions)


# Download Audit Logs
@app.route('/audit-logs/download')
@login_required(role='Admin')
def download_audit_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    data = [{
        'Action': log.action,
        'Filename': log.sop.filename if log.sop else '',
        'Performed By': log.username,
        'Timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M'),
        'Notes': log.notes or ''
    } for log in logs]

    df = pd.DataFrame(data)
    path = os.path.join(app.root_path, 'static', 'audit_trail_logs.xlsx')
    df.to_excel(path, index=False)
    return send_from_directory(directory='static', path='audit_trail_logs.xlsx', as_attachment=True)


# ✅ Mark individual SOP as read
@app.route('/read/<int:sop_id>')
@login_required()
def mark_as_read(sop_id):
    existing = ReadLog.query.filter_by(
        sop_id=sop_id, username=session['username']).first()
    if not existing:
        db.session.add(ReadLog(sop_id=sop_id, username=session['username']))
        db.session.commit()
    return redirect(url_for('list_sops'))


# ✅ Bulk mark multiple SOPs as read
@app.route('/mark-read', methods=['POST'])
@login_required()
def bulk_mark_as_read():
    selected_ids = request.form.getlist('sop_ids')
    username = session.get('username')

    user = User.query.filter_by(username=username).first()
    if not user:
        flash("User not found in the database.", "error")
        return redirect(url_for('list_sops'))

    for sop_id in selected_ids:
        # ✅ Mark as read if not already
        existing_read = ReadLog.query.filter_by(
            sop_id=sop_id, username=username).first()
        if not existing_read:
            db.session.add(ReadLog(sop_id=sop_id, username=username))

        # ✅ Acknowledge if assignment exists
        assignment = SOPAssignment.query.filter_by(
            sop_id=sop_id, user_id=user.id).first()
        if assignment and not assignment.acknowledged:
            assignment.acknowledged = True

    db.session.commit()
    flash(f"{len(selected_ids)} SOP(s) marked as read and acknowledged.", "success")
    return redirect(url_for('list_sops'))



# SOP acknowledgment
@app.route('/acknowledge/<int:sop_id>', methods=['POST'])
@login_required()
def acknowledge(sop_id):
    user_id = session.get('user_id')
    assignment = SOPAssignment.query.filter_by(
        user_id=user_id, sop_id=sop_id).first()
    if assignment:
        assignment.acknowledged = True
        db.session.commit()
        flash('SOP acknowledged successfully!', 'success')
    return redirect(url_for('documents_page'))  # or wherever appropriate


# Dashboard
# 📊 Dashboard
@app.route('/dashboard')
@login_required()
def dashboard():
    all_years = sorted({s.date_uploaded.year for s in SOP.query.filter(
        SOP.date_uploaded.isnot(None)).all()}, reverse=True)
    all_months = list(range(1, 13))
    all_categories = sorted(
        {s.category for s in SOP.query.filter(SOP.category.isnot(None)).all()})

    return render_template(
        "dashboard.html",
        years=all_years,
        months=all_months,
        all_categories=all_categories
    )

# 📊 AJAX ENDPOINT FOR CHART DATA
@app.route('/dashboard_data')
@login_required()
def dashboard_data():
    year = request.args.get('year', type=int)
    month = request.args.get('month', type=int)
    category = request.args.get('category')
    amendment_status = request.args.get('amendment_status')

    sop_query = SOP.query.filter(SOP.deleted == False)
    amendment_query = Amendment.query

    if year:
        sop_query = sop_query.filter(
            db.extract('year', SOP.date_uploaded) == year)
        amendment_query = amendment_query.filter(
            db.extract('year', Amendment.date_raised) == year)

    if month:
        sop_query = sop_query.filter(db.extract(
            'month', SOP.date_uploaded) == month)
        amendment_query = amendment_query.filter(
            db.extract('month', Amendment.date_raised) == month)

    if category:
        sop_query = sop_query.filter(SOP.category == category)

    if amendment_status == 'open':
        amendment_query = amendment_query.filter(Amendment.is_closed == False)
    elif amendment_status == 'closed':
        amendment_query = amendment_query.filter(Amendment.is_closed == True)

    # 📈 Uploads by month
    uploads_by_month = sop_query.with_entities(
        db.extract('month', SOP.date_uploaded).label('month'),
        db.func.count(SOP.id)
    ).group_by('month').all()

    uploads_data = [{"month": int(month), "count": count}
                    for month, count in uploads_by_month]

    # 📊 Draft vs Final from filtered Amendments
    draft_count = amendment_query.filter(Amendment.status == 'draft').count()
    final_count = amendment_query.filter(Amendment.status == 'final').count()

    # 🛠️ Amendments Raised vs Closed
    amendments_raised = amendment_query.count()
    amendments_closed = amendment_query.filter(
        Amendment.is_closed == True).count()

    # 📂 SOPs by Category
    category_stats = sop_query.with_entities(
        SOP.category, db.func.count(SOP.id)
    ).group_by(SOP.category).all()

    category_labels = [cat for cat, _ in category_stats]
    category_values = [count for _, count in category_stats]

    # ✅ 🆕 Calculate total uploads
    total_uploads = sum(u['count'] for u in uploads_data)

    return jsonify({
        "uploads_data": uploads_data,
        "draft_count": draft_count,
        "final_count": final_count,
        "amendments_raised": amendments_raised,
        "amendments_closed": amendments_closed,
        "category_labels": category_labels,
        "category_values": category_values,
        "total_uploads": total_uploads  # ✅ include in JSON
    })


# 📥 Download SOP
@app.route('/download/<filename>')
@login_required()
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


@app.context_processor
def inject_now():
    from datetime import datetime
    return {
        'current_year': datetime.now().year,
        'now': datetime.utcnow()
    }





# My Actions
@app.route('/my_actions')
@login_required()
def get_my_actions():
    username = session.get('username')
    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify([])

    # fetch SOPs assigned but not acknowledged
    assignments = SOPAssignment.query.filter_by(
        user_id=user.id, acknowledged=False).all()
    sop_ids = [a.sop_id for a in assignments]

    sops = SOP.query.filter(SOP.id.in_(sop_ids), SOP.deleted == False).all()

    return jsonify([{
        "id": sop.id,
        "title": sop.filename
    } for sop in sops])
    

@app.route('/assign_success_summary')
def assign_success_summary():
    assignments = SOPAssignment.query.order_by(
        SOPAssignment.date_assigned.desc()).all()
    return render_template('assign_success.html', assigned_users=assignments, sop_ids=[], sop_id=None, show_alert=False)


# Assign SOP
@app.route('/assign_sop', methods=['POST'])
@login_required(role=['Admin', 'Director', 'Head of Department'])
def assign_sop():
    sop_ids = request.form.getlist('sop_ids')
    user_ids = request.form.getlist('user_ids')
    user_role = request.form.get('user_role')
    assign_all = request.form.get('assign_all')
    first_sop_id = sop_ids[0] if sop_ids else None

    if not sop_ids:
        flash('No SOPs were selected for assignment.', 'error')
        return redirect(url_for('list_sops'))

    if assign_all:
        all_users = User.query.all()
        user_ids = [u.id for u in all_users]
    elif user_role:
        role_users = User.query.filter_by(role=user_role).all()
        user_ids.extend([u.id for u in role_users])
    else:
        user_ids = [int(uid) for uid in user_ids]

    user_ids = list(set(int(uid) for uid in user_ids))
    assigned_by = session['username']

    new_assignments = []

    for sop_id in sop_ids:
        sop = SOP.query.get(sop_id)
        if not sop:
            continue
        for user_id in user_ids:
            user = User.query.get(user_id)
            if user:
                existing = SOPAssignment.query.filter_by(
                    sop_id=sop_id, user_id=user.id).first()
                if not existing:
                    assignment = SOPAssignment(
                        user_id=user.id,
                        sop_id=sop.id,
                        assigned_by=assigned_by,
                        date_assigned=datetime.utcnow()
                    )
                    db.session.add(assignment)
                    new_assignments.append(assignment)
    db.session.commit()

    all_assignments = SOPAssignment.query.order_by(
        SOPAssignment.date_assigned.desc()).all()

    audit = AuditLog(
        action='assigned',
        username=assigned_by,
        notes=f"Assigned SOP(s) {', '.join(sop_ids)} to {len(user_ids)} users"
    )
    db.session.add(audit)
    db.session.commit()

    sop_ids = [int(sid) for sid in sop_ids]

    return render_template('assign_success.html',
                           assigned_users=all_assignments,
                           sop_ids=sop_ids,
                           sop_id=first_sop_id,
                           new_assignment_count=len(new_assignments),
                           show_alert=True)


@app.route('/assign_success/<int:sop_id>', endpoint='assign_success')
@login_required(role=['Admin', 'Director', 'Head of Department'])
def assign_success(sop_id):
    assignments = SOPAssignment.query.filter_by(sop_id=sop_id).all()
    sop = SOP.query.get(sop_id)
    # assigned_users = []
    assigned_users = SOPAssignment.query.filter_by(sop_id=sop_id).order_by(SOPAssignment.date_assigned.desc()).all()
    for a in assignments:
        assigned_users.append({
            'username': a.user.username if a.user else '',
            'role': a.user.role if a.user else '',
            'sop_name': sop.filename if sop else '',
            'date_assigned': a.date_assigned.strftime('%Y-%m-%d %H:%M:%S') if a.date_assigned else '',
            'assigned_by': a.assigned_by if a.assigned_by else '',
            'read_status': 'Read' if a.acknowledged else 'Unread',
            'date_read': a.date_read.strftime('%Y-%m-%d %H:%M:%S') if a.date_read else ''
        })
        
    return render_template('assign_success.html', assigned_users=assigned_users, sop_id=sop_id, show_alert=False)





@app.route('/export_assigned_users/<int:sop_id>')
@login_required(role=['Admin', 'Director', 'Head of Department'])
def export_assigned_users(sop_id):
    assignments = SOPAssignment.query.filter_by(sop_id=sop_id).all()
    data = []
    for a in assignments:
        data.append({
            'Username': a.user.username,
            'Full Name': a.user.fullname,
            'Role': a.user.role,
            'SOP Name': a.sop.filename,
            'Date Assigned': a.date_assigned.strftime('%Y-%m-%d %H:%M:%S') if a.date_assigned else '',
            'Assigned By': a.assigned_by if hasattr(a, 'assigned_by') else '',
            'Read Status': 'Read' if a.acknowledged else 'Unread',
            'Date Read': a.date_read.strftime('%Y-%m-%d %H:%M:%S') if a.date_read else ''
        })

    df = pd.DataFrame(data)
    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Assigned Users')
    output.seek(0)

    return send_file(output,
                     download_name=f'assigned_users_sop_{sop_id}.xlsx',
                     as_attachment=True,
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')


# Assign Page - GET route: Show Assign SOP Page
@app.route('/assign_page')
@login_required(role=['Admin', 'Director', 'Head of Department'])
def assign_page():
    sop_ids = request.args.getlist('sop_ids')
    if not sop_ids:
        sop_id = request.args.get('sop_id')  # fallback for single sop_id
        if sop_id:
            sop_ids = [sop_id]
    if not sop_ids:
        flash('No SOPs selected for assignment.', 'error')
        return redirect(url_for('list_sops'))
    sop_ids = [int(sid) for sid in sop_ids]
    sops = SOP.query.filter(SOP.id.in_(sop_ids)).all()
    users = User.query.all()
    roles = ['Admin', 'Director', 'Head of Department', 'Staff']
    return render_template('assign.html', sops=sops, users=users, roles=roles)


# View and submit amendments
@app.route('/amendments', methods=['GET', 'POST'])
@login_required()
def amendments_page():
    from datetime import datetime

    # ✅ Check if manage=true was passed
    manage = request.args.get('manage')
    if manage == "true":
        first_amendment = Amendment.query.first()
        if first_amendment:
            return redirect(url_for('manage_amendment', amendment_id=first_amendment.id, tab='stage2'))
        else:
            flash("No amendments available to manage.", "warning")
            return redirect(url_for('amendments_page'))

    status = request.args.get('status')  # ✅ Get filter status from query param


    if request.method == 'POST':
        sop_id = request.form.get('sop_id')
        sop = SOP.query.get_or_404(sop_id)
        new_amendment = Amendment(
            sop_id=sop_id,
            raised_by=session['username'],
            sop_section=request.form.get('sop_section'),
            details=request.form.get('details'),
            suggestion=request.form.get('suggestion'),
            severity=request.form.get('severity'),
            sop_version=sop.version,
            owner=sop.uploaded_by,
            status=request.form.get('status')
        )
        db.session.add(new_amendment)

        # ✅ Log to audit trail
        db.session.add(AuditLog(
            sop_id=sop.id,
            sop_filename=sop.filename,
            username=session['username'],
            action='amendment_raised',
            notes=f"Amendment for SOP section: {new_amendment.sop_section}"
        ))

        db.session.commit()

        # ✅ Get recipient users
        user = User.query.filter_by(username=session['username']).first()
        sop_owner = User.query.filter_by(username=sop.uploaded_by).first()
        admins = User.query.filter(User.role == 'Admin').all()
        hods = User.query.filter(User.role == 'Head of Department').all()

        # ✅ Collect emails and user objects
        recipient_users = [user] + admins + hods
        if sop_owner and sop_owner.username != user.username:
            recipient_users.append(sop_owner)

        # ✅ Deduplicate users by username
        unique_users = {u.username: u for u in recipient_users}.values()

        # ✅ Send email to each user with personalized template
        # Make sure this import is at the top
        from emails import build_amendment_submitted_email
        for u in unique_users:
            html_body = build_amendment_submitted_email(
                u, sop.filename, new_amendment)
            send_amendment_email(
                "📩 Amendment Submitted Notification", html_body, [u.email])

        flash("Amendment logged successfully and email notifications sent.", "success")
        return redirect(url_for('amendments_page'))

    amendments = Amendment.query.order_by(Amendment.date_raised.desc()).all()
    sops = SOP.query.filter_by(deleted=False).all()
    return render_template("amendments.html", amendments=amendments, sops=sops, now=datetime.utcnow())



# 🧾 View & Manage Amendments (Stage 2)
@app.route('/amendments/manage/<int:amendment_id>', methods=['GET', 'POST'])
@login_required(role=['Admin', 'Head of Department'])
def review_amendment(amendment_id):
    amendment = Amendment.query.get_or_404(amendment_id)

    if request.method == 'POST':
        # ✅ Update stage 2 fields
        amendment.update_details = request.form['update_details']
        amendment.updated_by = session['username']
        amendment.update_date = datetime.utcnow()

        # ✅ Check form inputs
        consensus = 'consensus' in request.form
        new_version = request.form.get('new_version', '').strip()
        close = bool(new_version)

        if consensus:
            amendment.consensus_reached = True

        # ✅ If closing amendment
        if consensus and close:
            amendment.is_closed = True
            amendment.closed_by = session['username']
            amendment.closed_date = datetime.utcnow()
            amendment.new_version = new_version

            # 📧 Notify stakeholders with formatted HTML email
            stakeholders = User.query.filter(User.role.in_(['Admin', 'Head of Department'])).all()
            for user in stakeholders:
                html_body = build_amendment_closed_email(user, amendment.sop.filename, amendment.update_details)
                send_amendment_email(
                    "SOP Amendment Closed",
                    html_body,
                    [user.email]
                )


        # 📝 Log to Audit
        db.session.add(AuditLog(
            sop_filename=amendment.sop.filename,
            username=session['username'],
            action='updated amendment',
            notes=f"Updated amendment ID {amendment.id} for {amendment.sop.filename}"
        ))

        db.session.commit()
        flash('Amendment updated.', 'success')
        return redirect(url_for('amendments_page'))

    return render_template('manage_amendment.html', amendment=amendment)


@app.route('/manage_amendment', methods=['GET', 'POST'])
@login_required()
def create_amendment():
    from datetime import datetime
    sops = SOP.query.filter_by(deleted=False).all()
    username = session.get('username')

    if request.method == 'POST':
        sop_id = request.form['sop_id']
        sop = SOP.query.get(sop_id)
        new_amendment = Amendment(
            sop_id=sop_id,
            raised_by=username,
            sop_section=request.form['sop_section'],
            details=request.form['details'],
            suggestion=request.form['suggestion'],
            severity=request.form['severity'],
            sop_version=sop.version,
            owner=sop.uploaded_by,
            status=request.form['status'],
            date_raised=datetime.utcnow()
        )
        db.session.add(new_amendment)
        db.session.commit()

        # ✅ Get recipient users
        user = User.query.filter_by(username=username).first()
        sop_owner = User.query.filter_by(username=sop.uploaded_by).first()
        admins = User.query.filter(User.role == 'Admin').all()
        hods = User.query.filter(User.role == 'Head of Department').all()

        # ✅ Collect emails and user objects
        recipient_users = [user] + admins + hods
        if sop_owner and sop_owner.username != username:
            recipient_users.append(sop_owner)

        # ✅ Deduplicate users by username
        unique_users = {u.username: u for u in recipient_users}.values()

        # ✅ Send email to each user with personalized template
        from emails import build_amendment_submitted_email
        for u in unique_users:
            html_body = build_amendment_submitted_email(u, sop.filename, new_amendment)
            send_amendment_email("📩 Amendment Submitted Notification", html_body, [u.email])

        flash("Amendment submitted successfully and email notifications sent.", "success")
        return redirect(url_for('amendments_page'))

    return render_template('manage_amendment.html', sops=sops)


@app.context_processor
def inject_pending_amendments():
    try:
        count = Amendment.query.filter_by(status='draft').count()
    except:
        count = 0
    return {'pending_amendments_count': count}




# 🔧 Route to raise or edit SOP amendments
@app.route('/manage_amendment/<int:amendment_id>', methods=['GET', 'POST'])
@login_required()
def manage_amendment(amendment_id=None):
    from datetime import datetime

    sops = SOP.query.filter_by(deleted=False).all()
    username = session.get('username')

    if amendment_id:
        amendment = Amendment.query.get_or_404(amendment_id)
        reviewed_amendments = Amendment.query.filter(
            Amendment.update_details.isnot(None)).all()  # ✅

        if request.method == 'POST':
            # Only allow editing if still in draft mode
            if amendment.status == 'draft':
                sop_id = request.form.get('sop_id')
                if sop_id:
                    amendment.sop_id = sop_id
                amendment.sop_section = request.form['sop_section']
                amendment.details = request.form['details']
                amendment.suggestion = request.form['suggestion']
                amendment.severity = request.form['severity']
                amendment.status = request.form['status']
                amendment.sop_version = SOP.query.get(amendment.sop_id).version
                amendment.owner = SOP.query.get(amendment.sop_id).uploaded_by
                db.session.commit()
                flash('Amendment updated successfully.', 'success')
                # <-- ✅ MUST BE inside the POST
                return redirect(url_for('amendments_page'))

        return render_template(
            'manage_amendment.html',
            amendment=amendment,
            reviewed_amendments=reviewed_amendments,
            sops=sops,
            default_tab='stage2'
        )

    # If NO amendment_id (creating new amendment)
    if request.method == 'POST':
        sop_id = request.form['sop_id']
        sop = SOP.query.get(sop_id)
        new_amendment = Amendment(
            sop_id=sop_id,
            raised_by=username,
            sop_section=request.form['sop_section'],
            details=request.form['details'],
            suggestion=request.form['suggestion'],
            severity=request.form['severity'],
            sop_version=sop.version,
            owner=sop.uploaded_by,
            status=request.form['status'],
            date_raised=datetime.utcnow()
        )
        db.session.add(new_amendment)
        db.session.commit()
        flash("Amendment submitted successfully.", "success")
        return redirect(url_for('amendments_page'))

    return render_template('manage_amendment.html', sops=sops)



# ✅ Close Amendment
@app.route('/amendments/close/<int:amendment_id>', methods=['POST'])
@login_required(role=['Admin', 'Head of Department'])
def close_amendment(amendment_id):
    amendment = Amendment.query.get_or_404(amendment_id)
    amendment.is_closed = True
    amendment.closed_by = session['username']
    amendment.closed_date = datetime.utcnow()
    amendment.new_version = request.form.get('new_version')

    db.session.add(AuditLog(
        sop_filename=amendment.sop.filename,
        username=session['username'],
        action='closed amendment',
        notes=f"Closed amendment ID {amendment.id} for {amendment.sop.filename}"
    ))

    db.session.commit()
    flash("Amendment closed successfully.", "success")
    return redirect(url_for('amendments_list'))


# 📄 List all amendments (like the Documents page)
@app.route('/amendments')
@login_required()
def list_amendments():
    from sqlalchemy import or_

    query = Amendment.query.join(SOP).filter(SOP.deleted == False)

    # Optional filters
    status = request.args.get('status')
    severity = request.args.get('severity')
    raised_by = request.args.get('raised_by')

    if status:
        query = query.filter(Amendment.status == status)
    if severity:
        query = query.filter(Amendment.severity == severity)
    if raised_by:
        query = query.filter(Amendment.raised_by == raised_by)

    amendments = query.order_by(Amendment.date_raised.desc()).all()

    status_options = ['draft', 'final']
    severity_options = ['Any', 'Critical', 'High', 'Medium',
                        'Low', 'Major', 'Minor', 'Query', 'Very High', 'Very Low']
    raised_by_options = [r[0]
                         for r in db.session.query(Amendment.raised_by).distinct()]

    return render_template(
        'amendments.html',
        amendments=amendments,
        status_options=status_options,
        severity_options=severity_options,
        raised_by_options=raised_by_options,
        selected_status=status,
        selected_severity=severity,
        selected_raised_by=raised_by
    )


# 📤 Export all amendment logs to Excel
@app.route('/amendments/export')
@login_required(role=['Admin'])
def export_amendments():
    amendments = Amendment.query.order_by(Amendment.date_raised.desc()).all()
    data = [{
        'SOP': a.sop.filename if a.sop else '',
        'Raised By': a.raised_by,
        'Date Raised': a.date_raised.strftime('%Y-%m-%d'),
        'Severity': a.severity,
        'Status': a.status,
        'Owner': a.owner,
        'Age (days)': (datetime.utcnow() - a.date_raised).days,
        'Update By': a.updated_by,
        'Update Date': a.update_date.strftime('%Y-%m-%d') if a.update_date else '',
        'Closed By': a.closed_by,
        'Closed Date': a.closed_date.strftime('%Y-%m-%d') if a.closed_date else '',
        'New Version': a.new_version,
        'Consensus': 'Yes' if a.consensus_reached else 'No'
    } for a in amendments]

    df = pd.DataFrame(data)
    path = os.path.join(app.root_path, 'static', 'amendment_logs.xlsx')
    df.to_excel(path, index=False)
    return send_from_directory(directory='static', path='amendment_logs.xlsx', as_attachment=True)


@app.template_filter('daysago')
def daysago(date):
    from datetime import datetime
    if not date:
        return ''
    days = (datetime.utcnow() - date).days
    if days == 0:
        return 'Today'
    elif days == 1:
        return '1 day ago'
    else:
        return f'{days} days ago'



# Edit Amendment
@app.route('/amendment/edit/<int:amendment_id>', methods=['GET', 'POST'])
@login_required()
def edit_amendment(amendment_id):
    amendment = Amendment.query.get_or_404(amendment_id)

    # ✅ Only allow editing if it's still a draft and raised by the current user
    if amendment.status != 'draft' or amendment.raised_by != session['username']:
        flash("You are not allowed to edit this amendment.", "warning")
        return redirect(url_for('amendments_page'))

    if request.method == 'POST':
        amendment.sop_section = request.form['sop_section']
        amendment.details = request.form['details']
        amendment.suggestion = request.form['suggestion']
        amendment.severity = request.form['severity']
        amendment.status = request.form['status']  # 'draft' or 'final'
        db.session.commit()
        flash("Amendment updated successfully.", "success")
        return redirect(url_for('amendments_page'))

    return render_template('edit_amendment.html', amendment=amendment)


# Admin Dashboard
@app.route('/admin')
@login_required(role='Admin')
def admin_dashboard():
    today = datetime.utcnow()
    last_7_days = [today - timedelta(days=i) for i in range(6, -1, -1)]

    visits_dates = [day.strftime("%d %b") for day in last_7_days]
    visits_counts = []

    for day in last_7_days:
        day_start = datetime(day.year, day.month, day.day, 0, 0, 0)
        day_end = datetime(day.year, day.month, day.day, 23, 59, 59)
        count = db.session.query(AuditLog).filter(
            AuditLog.action == 'login',
            AuditLog.timestamp.between(day_start, day_end)
        ).count()
        visits_counts.append(count)

    role_labels, role_counts = get_role_counts()

    total_users = User.query.count()
    active_users = User.query.filter_by(is_blocked=False).count()
    blocked_users = User.query.filter_by(is_blocked=True).count()
    total_sops = SOP.query.count()

    open_tickets = SupportTicket.query.filter_by(status='Open').count()
    closed_tickets = SupportTicket.query.filter_by(status='Closed').count()
    total_tickets = open_tickets + closed_tickets

    pending_tickets = open_tickets
    resolved_tickets = closed_tickets

    last_login = db.session.query(AuditLog.timestamp).filter_by(
        action='login').order_by(AuditLog.timestamp.desc()).first()
    last_login_date = last_login[0].strftime(
        "%d-%b-%Y %H:%M") if last_login else "No login yet"

    return render_template('admin/dashboard.html',
                           total_users=total_users,
                           active_users=active_users,
                           blocked_users=blocked_users,
                           total_sops=total_sops,
                           visits_dates=visits_dates,
                           visits_counts=visits_counts,
                           role_labels=role_labels,
                           role_counts=role_counts,
                           open_tickets=open_tickets,
                           closed_tickets=closed_tickets,
                           total_tickets=total_tickets,
                           pending_tickets=pending_tickets,
                           resolved_tickets=resolved_tickets,
                           last_login_date=last_login_date)


# Admin Manage Users Page
@app.route('/admin/users')
@login_required(role='Admin')
def admin_manage_users():
    users = User.query.all()
    total_users = User.query.count()
    active_users = User.query.filter_by(
        is_active=True, is_blocked=False).count()
    blocked_users = User.query.filter_by(is_blocked=True).count()
    suspended_users = User.query.filter_by(is_active=False).count()
    return render_template('admin/manage_users.html', users=users,
                           total_users=total_users, active_users=active_users,
                           blocked_users=blocked_users, suspended_users=suspended_users)



# Reset Password
@app.route('/admin/users/reset/<int:user_id>', methods=['POST'])
@login_required(role='Admin')
def reset_user_password(user_id):
    user = User.query.get_or_404(user_id)

    # 1. Generate random password
    random_password = generate_random_password()
    while not is_strong_password(random_password):
        random_password = generate_random_password()

    # 2. Hash and update in DB
    hashed_password = generate_password_hash(random_password)
    user.password_hash = hashed_password
    user.must_change = True
    db.session.commit()

    # 3. Build HTML email body (styled)
    html_body = f"""
    <div style="font-family: Arial, sans-serif; background-color: #f9f9f9; padding: 20px;">
        <div style="max-width: 600px; margin: auto; background: white; padding: 20px; border-radius: 8px;">
            <h2 style="color: #0044cc;">🔒 NHRC SOP Portal Password Reset</h2>
            <p>Hello <strong>{user.username}</strong>,</p>
            <p>Your password has been reset by the admin. Here is your new temporary password:</p>
            <p style="font-size: 18px; font-weight: bold; background-color: #eee; padding: 10px; border-radius: 5px;">
                {random_password}
            </p>
            <p>Please log in and change your password as soon as possible.</p>
            <p style="margin-top: 20px;">Regards,<br>NHRC SOP Portal Team</p>
        </div>
    </div>
    """

    # 4. Send the email
    try:
        send_email(
            user.email,
            "🔒 Password Reset Notification",
            html_body
        )
        flash('Password reset and email sent successfully.', 'success')
    except Exception as e:
        print(f"Failed to send password reset email: {str(e)}")
        flash('Password reset, but failed to send email.', 'error')

    return redirect(url_for('admin_manage_users'))









# Suspend/Activate User
@app.route('/admin/users/suspend/<int:user_id>')
@login_required(role='Admin')
def suspend_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    flash("User status updated.", "success")
    return redirect(url_for('admin_manage_users'))

# Promote User Role
@app.route('/admin/users/promote/<int:user_id>')
@login_required(role='Admin')
def promote_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == 'user':
        user.role = 'Head of Department'
    elif user.role == 'Head of Department':
        user.role = 'Admin'
    db.session.commit()
    flash("User role upgraded.", "success")
    return redirect(url_for('admin_manage_users'))

# Soft Delete User
@app.route('/admin/users/delete/<int:user_id>')
@login_required(role='Admin')
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_active = False
    user.is_blocked = True
    db.session.commit()
    flash("User suspended (soft delete).", "success")
    return redirect(url_for('admin_manage_users'))


@app.route('/admin/logs')
@login_required(role='Admin')
def admin_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()

    today = datetime.utcnow()
    last_7_days = [today - timedelta(days=i) for i in range(6, -1, -1)]
    chart_labels = [day.strftime("%d %b") for day in last_7_days]
    chart_counts = []

    for day in last_7_days:
        day_start = datetime(day.year, day.month, day.day, 0, 0, 0)
        day_end = datetime(day.year, day.month, day.day, 23, 59, 59)
        count = AuditLog.query.filter(
            AuditLog.timestamp.between(day_start, day_end)).count()
        chart_counts.append(count)

    return render_template('admin/view_logs.html', logs=logs,
                           chart_labels=chart_labels, chart_counts=chart_counts)

# Admin Notifications Center


@app.route('/admin/notifications', methods=['GET', 'POST'])
@login_required(role='Admin')
def admin_send_notification():
    if request.method == 'POST':
        title = request.form.get('title')
        message = request.form.get('message')
        target = request.form.get('target')
        method = request.form.get('method')

        if not title or not message or not target or not method:
            flash("All fields are required.", "error")
            return redirect(url_for('admin_send_notification'))

        # Select users based on target
        if target == 'all':
            users = User.query.all()
        else:
            users = User.query.filter_by(role=target).all()

        if method in ['email', 'both']:
            for user in users:
                send_email(
                    to_email=user.email,
                    subject=f"NHRC SOP Portal: {title}",
                    html_body=f"Dear {user.username},<br><br>{message}<br><br>Regards,<br>NHRC SOP Portal Team"
                )
                
        if method in ['popup', 'both']:
            for user in users:
                new_popup = Notification(
                    user_id=user.id,
                    title=title,
                    message=message,
                    seen=False
                )
                db.session.add(new_popup)

        db.session.commit()

        flash("Notification sent successfully!", "success")
        return redirect(url_for('admin_send_notification'))

    return render_template('admin/notifications.html')


@app.route('/mark_notification_seen', methods=['POST'])
@login_required()
def mark_notification_seen_view():  # <== not same as any other function name
    notification = Notification.query.filter_by(
        user_id=session['user_id'], seen=False).order_by(Notification.timestamp.desc()).first()
    if notification:
        notification.seen = True
        db.session.commit()
    return '', 204


@app.route('/admin/api_keys', methods=['GET', 'POST'])
@login_required(role='Admin')
def admin_api_keys():
    if request.method == 'POST':
        description = request.form.get('description')
        expires_at = request.form.get('expires_at')
        expires_at = datetime.strptime(
            expires_at, "%Y-%m-%d") if expires_at else None
        new_key = secrets.token_hex(32)
        api_key = APIKey(key=new_key, description=description,
                         expires_at=expires_at, created_by=session['username'])
        db.session.add(api_key)
        db.session.commit()
        flash('API Key created successfully.', 'success')
        return redirect(url_for('admin_api_keys'))

    api_keys = APIKey.query.order_by(APIKey.created_at.desc()).all()
    return render_template('admin/api_keys.html', api_keys=api_keys)



@app.route('/admin/api-keys/disable/<int:key_id>', methods=['POST'])
@login_required(role='Admin')
def disable_api_key(key_id):
    key = APIKey.query.get_or_404(key_id)
    key.active = False
    db.session.commit()
    flash('API Key disabled successfully.', 'success')
    return redirect(url_for('admin_api_keys'))


@app.route('/admin/api-keys/enable/<int:key_id>', methods=['POST'])
@login_required(role='Admin')
def enable_api_key(key_id):
    key = APIKey.query.get_or_404(key_id)
    key.active = True
    db.session.commit()
    flash('API Key enabled successfully.', 'success')
    return redirect(url_for('admin_api_keys'))


@app.route('/admin/api-keys/delete/<int:key_id>', methods=['POST'])
@login_required(role='Admin')
def delete_api_key(key_id):
    key = APIKey.query.get_or_404(key_id)
    db.session.delete(key)
    db.session.commit()
    flash('API Key deleted successfully.', 'success')
    return redirect(url_for('admin_api_keys'))


@app.route('/admin/api-keys/regenerate/<int:key_id>', methods=['POST'])
@login_required(role='Admin')
def regenerate_api_key(key_id):
    key = APIKey.query.get_or_404(key_id)
    key.key = secrets.token_hex(32)
    db.session.commit()
    flash('API Key regenerated successfully.', 'success')
    return redirect(url_for('admin_api_keys'))


# @app.route('/admin/settings')
# @login_required(role='Admin')
# def admin_settings():
#     return render_template('admin/settings.html')


@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required(role='Admin')
def admin_settings():
    settings = Setting.query.first()

    if request.method == 'POST':
        if not settings:
            settings = Setting()

        settings.portal_name = request.form['portal_name']
        settings.admin_email = request.form['admin_email']
        settings.theme_color = request.form['theme_color']
        settings.enable_registration = 'enable_registration' in request.form

        # Handle logo upload
        file = request.files.get('logo_upload')
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            file.save(os.path.join('static/uploads', filename))
            settings.logo_filename = filename

        db.session.add(settings)
        db.session.commit()
        flash('Settings updated successfully!', 'success')
        return redirect(url_for('admin_settings'))

    return render_template('admin/settings.html', settings=settings)

# 📋 Help Page Route
@app.route('/help')
@login_required()
def help_page():
    return render_template('help.html')

# 📜 Documentation Page Route
@app.route('/documentation')
@login_required()
def documentation_page():
    return render_template('documentation.html')


@app.route('/submit_support_ticket', methods=['POST'])
def submit_support_ticket():
    name = request.form.get('name')
    email = request.form.get('email')
    subject_line = request.form.get('subject')
    message = request.form.get('message')

    # Save the ticket
    new_ticket = SupportTicket(
        name=name,
        email=email,
        subject=subject_line,
        message=message,
        submitted_at=datetime.utcnow(),
        status='Open'
    )
    db.session.add(new_ticket)
    db.session.commit()

    # Generate ticket ID (if you want to include one)
    ticket_id = f"NHRC-TKT-{new_ticket.id:05d}"
    new_ticket.ticket_id = ticket_id
    db.session.commit()

    # Build email bodies
    from emails import build_support_ticket_user_email, build_support_ticket_admin_email

    user_html = build_support_ticket_user_email(name, subject_line, message, ticket_id)
    admin_html = build_support_ticket_admin_email(name, email, subject_line, message, ticket_id)

    # Get admin emails
    admin_users = User.query.filter(User.role == 'Admin').all()
    admin_emails = [u.email for u in admin_users]

    # Send emails
    send_amendment_email(f"🆘 Ticket Received: {subject_line}", user_html, [email])
    send_amendment_email(f"📢 New Support Ticket: {subject_line}", admin_html, admin_emails)

    flash('✅ Your support request has been submitted. You will receive an email confirmation shortly.', 'success')
    return redirect(url_for('help_page'))





@app.route('/admin/support-tickets/resolve/<int:ticket_id>', methods=['POST'])
@login_required(role='Admin')
def resolve_support_ticket(ticket_id):
    ticket = SupportTicket.query.get_or_404(ticket_id)
    ticket.status = 'Resolved'
    db.session.commit()
    flash('✅ Ticket marked as resolved.', 'success')
    return redirect(url_for('view_support_tickets'))




# 📩 Support Tickets (Admin Panel)
# View all Support Tickets
@app.route('/admin/support-tickets')
@login_required(role='Admin')
def support_tickets():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    status = request.args.get('status')

    # Map incoming 'Closed / Resolved' to 'Closed' for backend logic
    if status == 'Closed / Resolved':
        status = 'Closed'

    # Base query
    query = SupportTicket.query

    # Apply status filter
    if status == 'Open':
        query = query.filter(SupportTicket.status == 'Open')
    elif status == 'Closed':
        query = query.filter(SupportTicket.status.in_(['Closed', 'Resolved']))

    # Paginate results
    tickets = query.order_by(SupportTicket.submitted_at.desc()).paginate(
        page=page, per_page=per_page)

    # Counts
    open_count = SupportTicket.query.filter_by(status='Open').count()
    closed_count = SupportTicket.query.filter(
        SupportTicket.status.in_(['Closed', 'Resolved'])).count()

    return render_template('admin/support_tickets.html',
                           tickets=tickets,
                           open_count=open_count,
                           closed_count=closed_count,
                           current_status=status or 'All')




# 🗑️ Delete a Support Ticket (called via fetch DELETE)
# Delete Support Ticket (POST version)
@app.route('/admin/support-tickets/delete/<int:ticket_id>', methods=['POST'])
@admin_required
def delete_support_ticket(ticket_id):
    ticket = SupportTicket.query.get_or_404(ticket_id)

    try:
        db.session.delete(ticket)
        db.session.commit()
        flash('Ticket deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting ticket: {str(e)}', 'danger')

    return redirect(url_for('support_tickets'))


# ✉️ Reply to Support Ticket
@app.route('/reply_ticket/<int:ticket_id>', methods=['POST'])
@login_required(role='Admin')
def reply_ticket(ticket_id):
    ticket = SupportTicket.query.get_or_404(ticket_id)
    reply_message = request.form.get('reply_message')

    if not reply_message:
        return jsonify({"success": False, "message": "Reply message is required."})

    try:
        # Save the reply message
        ticket.reply_message = reply_message
        ticket.status = 'Closed'  # ✅ Mark ticket as Closed after reply
        db.session.commit()

        # Send reply email
        send_email(
            subject=f"Reply to your Ticket: {ticket.subject}",
            to_email=ticket.email,
            body=f"Dear {ticket.name},\n\n{reply_message}\n\nBest regards,\nNHRC SOP Portal Support Team"
        )

        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})



# ✉️ Reply to a Support Ticket (AJAX POST from reply modal)
# @app.route('/reply_ticket/<int:ticket_id>', methods=['POST'])
# @admin_required
# def reply_ticket(ticket_id):
#     ticket = SupportTicket.query.get_or_404(ticket_id)
#     your_reply_message = request.form.get('reply_message')

#     if not your_reply_message:
#         return jsonify(success=False, message="Reply message is required.")

#     # Update ticket reply and close it
#     ticket.reply_message = your_reply_message
#     ticket.status = 'Closed'
#     db.session.commit()

#     # Build and send email
#     email_subject = f"Re: {ticket.subject}"
#     email_body = f"""Hi {ticket.name},

# Thank you for contacting support.

# {your_reply_message}

# ---

# Original Message:
# "{ticket.message}"

# Best regards,
# NHRC SOP Portal Team
# """

#     try:
#         send_email(subject=email_subject,
#                    to_email=ticket.email, body=email_body)
#         return jsonify(success=True, message="Reply sent successfully!")
#     except Exception as e:
#         return jsonify(success=False, message=f"Failed to send email: {str(e)}")

# 📩 Open the reply page
@app.route('/reply_ticket/<int:ticket_id>', methods=['GET'])
@login_required(role='Admin')
def reply_ticket_page(ticket_id):
    ticket = SupportTicket.query.get_or_404(ticket_id)
    return render_template('admin/reply_ticket.html', ticket=ticket)

# 📩 Submit the reply
# @app.route('/send_reply/<int:ticket_id>', methods=['POST'])
# @login_required(role='Admin')
# def send_reply(ticket_id):
#     ticket = SupportTicket.query.get_or_404(ticket_id)
#     reply_message = request.form.get('reply_message')

#     if not reply_message:
#         flash("Reply message cannot be empty.", "error")
#         return redirect(url_for('reply_ticket_page', ticket_id=ticket_id))

#     ticket.reply_message = reply_message
#     ticket.status = 'Closed'
#     db.session.commit()

#     # Send email
#     send_email(
#         subject=f"Reply to your Ticket: {ticket.subject}",
#         to_email=ticket.email,
#         body=f"Dear {ticket.name},\n\n{reply_message}\n\nBest regards,\nNHRC SOP Portal Support Team"
#     )

#     flash("Reply sent successfully.", "success")
#     return redirect(url_for('support_tickets'))


# 📥 Export Support Tickets to Excel
@app.route('/admin/tickets/export')
@login_required(role='Admin')
def export_tickets():
    tickets = SupportTicket.query.order_by(
        SupportTicket.submitted_at.desc()).all()

    data = []
    for ticket in tickets:
        data.append({
            'ID': ticket.id,
            'Subject': ticket.subject,
            'Email': ticket.email,
            'Message': ticket.message,
            'Status': ticket.status,
            'Date Submitted': ticket.submitted_at.strftime("%Y-%m-%d %H:%M")
        })

    df = pd.DataFrame(data)

    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Support Tickets')

    output.seek(0)

    return send_file(output, download_name="support_tickets.xlsx", as_attachment=True)


@app.route('/admin/tickets/refresh')
@admin_required
def refresh_tickets():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    tickets = SupportTicket.query.order_by(
        SupportTicket.submitted_at.desc()).paginate(page=page, per_page=per_page)

    return render_template('admin/partials/_tickets_table.html', tickets=tickets)


def send_email(to_email, subject, html_body):
    try:
        msg = Message(
            subject=subject,
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=[to_email] if isinstance(
                to_email, list) else [to_email],
        )
        msg.body = "This is an HTML email. Please use an email client that supports HTML."
        msg.html = html_body
        mail.send(msg)
    except Exception as e:
        print(f"Failed to send email: {str(e)}")


# 📧 Function to Send Reply Email
def send_reply_email(recipient_email, subject, reply_message):
    try:
        # Send Admin Reply
        msg = Message(
            subject=f"RE: {subject}",
            sender=app.config['MAIL_USERNAME'],
            recipients=[recipient_email],
            body=f"Hello,\n\n{reply_message}\n\nThank you,\nNHRC SOP Support Team"
        )
        mail.send(msg)

        # Also send Thank You Email Automatically
        thank_you = Message(
            subject=f"Thank you for contacting NHRC SOP Support!",
            sender=app.config['MAIL_USERNAME'],
            recipients=[recipient_email],
            body=f"Hi,\n\nWe have received your support request and our team has replied to you.\n\nThank you for using NHRC SOP Portal.\n\nBest regards,\nNHRC SOP Support Team"
        )
        mail.send(thank_you)

    except Exception as e:
        print(f"Error sending email: {e}")


@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required(role='Admin')
def edit_user(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        user.role = request.form['role']
        db.session.commit()

        flash('✅ User updated successfully!', 'success')
        return redirect(url_for('admin_manage_users'))

    return render_template('edit_user.html', user=user)


@app.route('/admin/users/bulk', methods=['POST'])
@login_required(role='Admin')
def bulk_action_users():
    user_ids = request.form.getlist('user_ids')
    action = request.form.get('action')

    if not user_ids:
        flash('⚠️ No users selected.', 'error')
        return redirect(url_for('admin_manage_users'))

    success_count = 0

    for user_id in user_ids:
        user = User.query.get(user_id)
        if not user:
            continue  # Skip missing users

        if action == 'delete':
            db.session.delete(user)
            success_count += 1

        elif action == 'reset':
            random_password = generate_random_password()
            user.password_hash = generate_password_hash(random_password)
            user.must_change = True

            # Send reset email
            html_body = build_password_reset_email(user, random_password)
            
            send_email(
                user.email,
                "🔒 Password Reset Notification",
                html_body
            )
            success_count += 1

        elif action == 'suspend':
            user.is_active = False
            success_count += 1

        elif action == 'activate':
            user.is_active = True
            success_count += 1

        elif action == 'promote':
            if user.role != 'Admin':
                user.role = 'Admin'
                success_count += 1

    db.session.commit()

    if success_count > 0:
        flash(
            f'✅ Bulk "{action.capitalize()}" action completed for {success_count} user(s).', 'success')
    else:
        flash('⚠️ No valid users processed.', 'error')

    return redirect(url_for('admin_manage_users'))


# @app.route('/documentation/pdf')
# @login_required()
# def download_documentation_pdf():
#     from weasyprint import HTML
#     from flask import make_response
#     html = render_template('documentation.html')
#     pdf = HTML(string=html).write_pdf()
#     response = make_response(pdf)
#     response.headers['Content-Type'] = 'application/pdf'
#     response.headers['Content-Disposition'] = 'attachment; filename=documentation.pdf'
#     return response

@app.route('/download-documentation-pdf')
@login_required()
def download_documentation_pdf():
    html = render_template('documentation.html')
    options = {
        'enable-local-file-access': ''
    }
    pdf = pdfkit.from_string(
        html, False, configuration=config, options=options)
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=documentation.pdf'
    return response



@app.route('/training-manual')
@login_required()
def training_manual():
    return render_template('training_manual.html')


@app.route('/training-manual/pdf')
@login_required()
def download_training_manual_pdf():
    from weasyprint import HTML
    from flask import make_response
    from datetime import datetime

    html = render_template('training_manual_pdf.html', date=datetime.utcnow().strftime('%B %d, %Y'))
    pdf = HTML(string=html, base_url=request.base_url).write_pdf()

    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=training_manual.pdf'

    return response



# -----------------------------
# ▶️ Run App
# -----------------------------    

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    print("🚀 Starting SOP App...")
    app.run(debug=True)
