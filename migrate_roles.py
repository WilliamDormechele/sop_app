from app import app, db, User

role_mapping = {
    'admin': 'Admin',
    'director': 'Director',
    'hod': 'Head of Department',
    'ro': 'Research Officer',
    'ra': 'Research Assistant',
    'nss': 'National Service Personnel',
    'guest': 'Guest',
    'monitor': 'Monitor',
    'js': 'Junior Staff'
}

with app.app_context():
    users = User.query.all()
    updated_count = 0
    for user in users:
        old_role = user.role
        if old_role in role_mapping:
            user.role = role_mapping[old_role]
            updated_count += 1
    db.session.commit()
    print(
        f"✅ Roles updated successfully. Total users updated: {updated_count}")
