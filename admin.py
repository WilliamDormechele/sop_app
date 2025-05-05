from app import app, db, User

with app.app_context():
    email = 'williamdormechele@gmail.com'
    username = 'admin'
    password = 'admin@94'

    existing_user = User.query.filter_by(email=email).first()

    if existing_user:
        print(
            f"⚠️ User already exists: {existing_user.username} ({existing_user.email})")
    else:
        admin = User(
            username=username,
            email=email,
            role='Admin',  # ✅ use capital A to match ROLE_CHOICES
            must_change=True
        )
        admin.set_password(password)  # ✅ store hashed password
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin user created successfully:")
        print(f"🔐 Username: {username}")
        print(f"🔑 Password: {password}")
