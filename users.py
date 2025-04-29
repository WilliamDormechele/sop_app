from app import app, db, User
with app.app_context():
    email = 'yassanwilliam66@gmail.com'
    username = 'hodcsd'
    password = 'test@94'

    existing_user = User.query.filter_by(email=email).first()

    if existing_user:
        print(
            f"⚠️ User already exists: {existing_user.username} ({existing_user.email})")
    else:
        admin = User(
            username=username,
            password=password,
            email=email,
            role='hod',
            must_change=True
        )
        db.session.add(admin)
        db.session.commit()
        print("✅ User created successfully:")
        print(f"🔐 Username: {username}")
        print(f"🔑 Password: {password}")


from app import app, db, User
with app.app_context():
    email = 'william.dormechele@navrongo-hrc.org'
    username = 'wdormechele'
    password = 'test@94'

    existing_user = User.query.filter_by(email=email).first()

    if existing_user:
        print(
            f"⚠️ User already exists: {existing_user.username} ({existing_user.email})")
    else:
        admin = User(
            username=username,
            password=password,
            email=email,
            role='ra',
            must_change=True
        )
        db.session.add(admin)
        db.session.commit()
        print("✅ User created successfully:")
        print(f"🔐 Username: {username}")
        print(f"🔑 Password: {password}")



# from app import app, db, User
# with app.app_context():
#     email = 'yassanwilliam68@gmail.com'
#     username = 'researchOfficer'
#     password = 'test@94'

#     existing_user = User.query.filter_by(email=email).first()

#     if existing_user:
#         print(
#             f"⚠️ User already exists: {existing_user.username} ({existing_user.email})")
#     else:
#         admin = User(
#             username=username,
#             password=password,
#             email=email,
#             role='ro',
#             must_change=True
#         )
#         db.session.add(admin)
#         db.session.commit()
#         print("✅ User created successfully:")
#         print(f"🔐 Username: {username}")
#         print(f"🔑 Password: {password}")


# from app import app, db, User

# with app.app_context():
#     email = 'yassanwilliam69@gmail.com'
#     username = 'researchOfficer'
#     password = 'test@94'

#     existing_user = User.query.filter_by(email=email).first()

#     if existing_user:
#         print(
#             f"⚠️ User already exists: {existing_user.username} ({existing_user.email})")
#     else:
#         admin = User(
#             username=username,
#             password=password,
#             email=email,
#             role='ro',
#             must_change=True
#         )
#         db.session.add(admin)
#         db.session.commit()
#         print("✅ User created successfully:")
#         print(f"🔐 Username: {username}")
#         print(f"🔑 Password: {password}")


# from app import app, db, User
# with app.app_context():
#     email = 'yassanwilliam70@gmail.com'
#     username = 'director'
#     password = 'test@94'

#     existing_user = User.query.filter_by(email=email).first()

#     if existing_user:
#         print(
#             f"⚠️ User already exists: {existing_user.username} ({existing_user.email})")
#     else:
#         admin = User(
#             username=username,
#             password=password,
#             email=email,
#             role='director',
#             must_change=True
#         )
#         db.session.add(admin)
#         db.session.commit()
#         print("✅ User created successfully:")
#         print(f"🔐 Username: {username}")
#         print(f"🔑 Password: {password}")


# from app import app, db, User
# with app.app_context():
#     email = 'yassanwilliam71@gmail.com'
#     username = 'guest'
#     password = 'test@94'

#     existing_user = User.query.filter_by(email=email).first()

#     if existing_user:
#         print(
#             f"⚠️ User already exists: {existing_user.username} ({existing_user.email})")
#     else:
#         admin = User(
#             username=username,
#             password=password,
#             email=email,
#             role='guest',
#             must_change=True
#         )
#         db.session.add(admin)
#         db.session.commit()
#         print("✅ User created successfully:")
#         print(f"🔐 Username: {username}")
#         print(f"🔑 Password: {password}")


# from app import app, db, User
# with app.app_context():
#     email = 'yassanwilliam72@gmail.com'
#     username = 'monitor'
#     password = 'test@94'

#     existing_user = User.query.filter_by(email=email).first()

#     if existing_user:
#         print(
#             f"⚠️ User already exists: {existing_user.username} ({existing_user.email})")
#     else:
#         admin = User(
#             username=username,
#             password=password,
#             email=email,
#             role='monitor',
#             must_change=True
#         )
#         db.session.add(admin)
#         db.session.commit()
#         print("✅ User created successfully:")
#         print(f"🔐 Username: {username}")
#         print(f"🔑 Password: {password}")


# from app import app, db, User
# with app.app_context():
#     email = 'yassanwilliam73@gmail.com'
#     username = 'juniorStaff'
#     password = 'test@94'

#     existing_user = User.query.filter_by(email=email).first()

#     if existing_user:
#         print(
#             f"⚠️ User already exists: {existing_user.username} ({existing_user.email})")
#     else:
#         admin = User(
#             username=username,
#             password=password,
#             email=email,
#             role='js',
#             must_change=True
#         )
#         db.session.add(admin)
#         db.session.commit()
#         print("✅ User created successfully:")
#         print(f"🔐 Username: {username}")
#         print(f"🔑 Password: {password}")
