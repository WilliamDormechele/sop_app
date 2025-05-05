from app import app, db, Log


with app.app_context():
    db.create_all()
    print("Tables created successfully!")
