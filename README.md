# NHRC SOP Portal

This is a Flask-based web application for managing Standard Operating Procedures (SOPs), user roles, audit logs, notifications, and support tickets in a research or institutional setting.

## 🔧 Features

- User authentication with roles (Admin, HOD, User)
- Upload, approve, and version control for SOP documents
- SOP assignment and acknowledgment tracking
- Amendment tracking with two-stage workflow
- Email notifications for SOPs and support responses
- Admin dashboard with user and SOP statistics
- Support ticket management system

## 🚀 Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/your-username/nhrc-sop-portal.git
cd nhrc-sop-portal
```

### 2. Create a virtual environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Set environment variables

Create a `.env` file and configure the following:

```env
FLASK_APP=app.py
FLASK_ENV=development
MAIL_USERNAME=your_email@example.com
MAIL_PASSWORD=your_app_password
SECRET_KEY=your_secret_key
```

### 5. Run the app

```bash
flask db upgrade  # Set up the database
flask run
```

Visit [http://localhost:5000](http://localhost:5000) in your browser.

## 📁 Project Structure

- `app.py` - Main Flask application file
- `templates/` - HTML templates
- `static/` - CSS, JS, uploads
- `uploads/` - Uploaded SOP files
- `env.py` - Alembic environment for migrations

## 📬 Contact

For any issues, please contact the admin via the support system in the portal.

---

© 2025 NHRC SOP Portal
