from app import db, User, app

with app.app_context():
    user = User.query.filter_by(username='atauwu').first()
    if user:
        print("✅ Found admin:")
        print("Username:", user.username)
        print("Hashed Password:", user.password)
        print("Is Admin:", user.is_admin)
    else:
        print("❌ Admin not found in database")
