from app import app, db, User, Setting

with app.app_context():
    db.drop_all()
    db.create_all()
    print("✅ All tables created!")

    # Add admin user
    admin = User(username='admin', email='williamdormechele@gmail.com',
                 role='admin', must_change=True)
    admin.set_password('admin@94')
    db.session.add(admin)

    # Add default setting row
    setting = Setting(
        portal_name='NHRC SOP Portal',
        admin_email='williamdormechele@gmail.com',
        logo_filename='logo.png',
        theme_color='#0044cc',
        enable_registration=True
    )
    db.session.add(setting)

    db.session.commit()
    print("✅ Admin and setting added!")
