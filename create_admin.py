from app import db, User, app
from werkzeug.security import generate_password_hash

new_password = 'SweetPass123'
hashed_pw = generate_password_hash(new_password)

with app.app_context():
    admin = User(username='atauwu', password=hashed_pw, is_admin=True)
    db.session.add(admin)
    db.session.commit()
    print(f"✅ New admin created: atauwu / {new_password}")
