from app import db, app

with app.app_context():
    db.drop_all()     # 🧨 Delete all tables
    db.create_all()   # 🆕 Recreate all tables
