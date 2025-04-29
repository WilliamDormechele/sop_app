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
            password=password,
            email=email,
            role='admin',
            must_change=True
        )
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin user created successfully:")
        print(f"🔐 Username: {username}")
        print(f"🔑 Password: {password}")


# 🔥 TEMPORARY: Create missing tables (like support_ticket)
# with app.app_context():
#     db.create_all()


# Create settings
# from app import app, db, Setting

# with app.app_context():
#     db.create_all()

#     default_setting = Setting(
#         portal_name="NHRC SOP Portal",
#         admin_email="awilliamdormechele@gmail.com",
#         logo_filename="default_logo.png",
#         theme_color="Blue",
#         enable_registration=True
#     )

#     db.session.add(default_setting)
#     db.session.commit()

# print("✅ Setting table created and default inserted successfully!")
