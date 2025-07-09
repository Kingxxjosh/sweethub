from app import app, db, User
from werkzeug.security import generate_password_hash

# Wrap everything inside app context
with app.app_context():
    admin = User.query.filter_by(username='atauwu').first()
    if admin:
        admin.password = generate_password_hash('SweetPass123')
        db.session.commit()
        print("✅ Admin password updated to: SweetPass123")
    else:
        print("❌ Admin user 'atauwu' not found.")
