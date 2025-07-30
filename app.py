from flask import Flask, render_template, request, redirect, session, url_for, send_from_directory, jsonify, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, join_room, emit
import os
import uuid
import sqlite3
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

from dotenv import load_dotenv
load_dotenv()

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")


# ✅ Initialize Flask app
app = Flask(__name__)
app.secret_key = 'sweet_secret_key'

# ✅ Configure SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///your_database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ✅ Define Video model
class Video(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    category = db.Column(db.String(100))
    country = db.Column(db.String(100))
    version = db.Column(db.String(100))
    uploader = db.Column(db.String(100))
    views = db.Column(db.Integer, default=0)
    likes = db.Column(db.Integer, default=0)
    video_url = db.Column(db.String(300))
    thumbnail_url = db.Column(db.String(300))

# ✅ Define Comment model
class Comment(db.Model): 
    id = db.Column(db.Integer, primary_key=True)
    video_id = db.Column(db.Integer, db.ForeignKey('video.id'), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    video = db.relationship('Video', backref=db.backref('comments', lazy=True))

# ✅ Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    wallet = db.Column(db.Float, default=0.0)
    is_admin = db.Column(db.Boolean, default=False)

# ✅ Initialize SocketIO
socketio = SocketIO(app)

# ✅ Users online list
users_online = []

# ✅ Force age confirmation before accessing most pages
@app.before_request
def require_age_confirmation():
    allowed_routes = [
        'age_confirmation', 'static', 'login', 'register', 'model_login',
        'register_model', 'logout', 'paystack_callback'
    ]

    if 'age_confirmed' not in session and request.endpoint not in allowed_routes:
        return redirect(url_for('age_confirmation'))

# ✅ Age confirmation page
@app.route('/age-confirmation', methods=['GET', 'POST'])
def age_confirmation():
    if request.method == 'POST':
        session['age_confirmed'] = True
        return redirect(url_for('home'))
    return render_template('age_gate.html')

# ✅ Home page — requires age confirmation
@app.route('/')
def home():
    videos = Video.query.order_by(Video.id.desc()).all()
    comments = Comment.query.all()
    return render_template('home.html', videos=videos, comments=comments)

# ✅ Chat join event
@socketio.on('join')
def handle_join(data):
    username = session.get('username', 'Guest')
    room = data['room']
    join_room(room)
    emit('receive_message', {
        'sender': 'System',
        'content': f'{username} joined {room}',
        'room': room,
        'type': 'text'
    }, room=room)

# ✅ Chat message event
@socketio.on('send_message')
def handle_message(data):
    emit('receive_message', data, room=data['room'])

# ✅ Online user request
@socketio.on('request_users')
def handle_user_list():
    emit('user_list', users_online)

# ✅ Connect to SQLite
def get_db():
    conn = sqlite3.connect('sweet.db')
    conn.row_factory = sqlite3.Row
    return conn

# ✅ Deduct SweetCoins
def deduct_coins(username, amount):
    conn = get_db()
    user = conn.execute("SELECT sweetcoins FROM users WHERE username = ?", (username,)).fetchone()
    if user and user["sweetcoins"] >= amount:
        conn.execute("UPDATE users SET sweetcoins = sweetcoins - ? WHERE username = ?", (amount, username))
        conn.commit()
        return True
    return False

@app.route("/unlock_model/<model_username>")
def unlock_model(model_username):
    username = session.get("username")
    if not username:
        return redirect(url_for("login"))

    conn = get_db()
    user = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    model = conn.execute("SELECT id FROM users WHERE username = ?", (model_username,)).fetchone()

    if not user or not model:
        return "User or model not found"

    # Check if already unlocked
    unlocked = conn.execute(
        "SELECT * FROM unlocks WHERE user_id = ? AND model_id = ?", (user['id'], model['id'])
    ).fetchone()

    if unlocked:
        return redirect(url_for("channel", username=model_username))

    # Deduct coins and save unlock
    if not deduct_coins(username, 20):
        return "❌ Not enough SweetCoins to unlock model content."

    conn.execute("INSERT INTO unlocks (user_id, model_id) VALUES (?, ?)", (user['id'], model['id']))
    conn.commit()

    return redirect(url_for("channel", username=model_username))

@app.route("/buy_coins")
def buy_coins():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template("buy_coins.html", PAYSTACK_PUBLIC=PAYSTACK_PUBLIC)

@app.route('/paystack_callback')
def paystack_callback():
    username = session.get('username')
    if not username:
        return redirect(url_for('login'))

    # Get number of coins from Paystack redirect (e.g., /paystack_callback?coins=1)
    coins = int(request.args.get("coins", 1))  # Default to 1 SweetCoin if not provided

    conn = get_db()
    conn.execute("UPDATE users SET sweetcoins = sweetcoins + ? WHERE username = ?", (coins, username))
    conn.commit()

    flash(f"✅ {coins} SweetCoin{'s' if coins > 1 else ''} successfully added to your wallet!")
    return redirect(url_for('messenger'))

UPLOAD_FOLDER = 'static/uploads'
PROFILE_PICS_FOLDER = 'static/profile_pics'
ALLOWED_VIDEO_EXTENSIONS = {'mp4'}
ALLOWED_IMAGE_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['PROFILE_PICS_FOLDER'] = PROFILE_PICS_FOLDER

# Storage
videos = []
users = []
comments = []

# Admin credentials
ADMIN_USERNAME = 'Atauwu'
ADMIN_PASSWORD = 'SweetPass123'  # Plain text password

PAYSTACK_PUBLIC = 'pk_test_1dc053fe95bf35500306a9c3cb32fb48be44dc20'
PAYSTACK_SECRET = 'sk_test_09a74040b27adc00d8d4d465b60e20c37d655f1f'

# Static Options
CATEGORIES = [
    'Amateur', 'Teen', 'Mature', 'Couple', 'Lesbian', 'Solo', 'Outdoor', 'BDSM', 'MILF', 'Ebony',
    'Anal', 'Asian', 'BBW', 'Blonde', 'Blowjob', 'Brunette', 'Creampie', 'Double Penetration',
    'Facial', 'Feet', 'Fetish', 'Gangbang', 'Hardcore', 'Interracial', 'Latina', 'Massage',
    'POV', 'Public', 'Threesome', 'Toys'
]
VERSIONS = ['HD', '4K', 'SD']
COUNTRIES = COUNTRIES = [
    "🇬🇭",  # Ghana
    "🇳🇬",  # Nigeria
    "🇺🇸",  # USA
    "🇬🇧",  # UK
    "🇩🇪",  # Germany
    "🇧🇷",  # Brazil
    "🇫🇷",  # France
    "🇯🇵",  # Japan
    "🇨🇦",  # Canada
    "🇰🇪",  # Kenya
    "🇲🇽",  # Mexico
    "🇮🇹",  # Italy
    "🇪🇸",  # Spain
    "🇿🇦",  # South Africa
    "🇷🇺",  # Russia
    "🇮🇳",  # India
    "🇦🇺",  # Australia
    "🇨🇳",  # China
    "🇹🇷",  # Turkey
    "🇳🇱",  # Netherlands
    "🇪🇬",  # Egypt
    "🇲🇦",  # Morocco
    "🇦🇷",  # Argentina
    "🇨🇴",  # Colombia
    "🇵🇭",  # Philippines
    "🇹🇭",  # Thailand
    "🇻🇳",  # Vietnam
    "🇸🇪",  # Sweden
    "🇳🇴",  # Norway
    "🇫🇮",  # Finland
    "🇩🇰",  # Denmark
    "🇧🇪",  # Belgium
    "🇵🇹",  # Portugal
    "🇺🇦",  # Ukraine
    "🇵🇱",  # Poland
    "🇭🇺",  # Hungary
    "🇬🇷",  # Greece
    "🇮🇩",  # Indonesia
    "🇲🇾",  # Malaysia
    "🇵🇰",  # Pakistan
    "🇧🇩",  # Bangladesh
    "🇮🇶",  # Iraq
    "🇮🇷",  # Iran
    "🇮🇱",  # Israel
    "🇸🇦",  # Saudi Arabia
    "🇦🇪",  # UAE
    "🇶🇦",  # Qatar
    "🇸🇬",  # Singapore
    "🇨🇭",  # Switzerland
    "🇳🇿"   # New Zealand
]


# --- Helpers ---
def allowed_file(filename, allowed_exts):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_exts

def get_current_user():
    username = session.get("username")
    return next((u for u in users if u['username'] == username), None)

# --- Routes ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form
        if data['password'] != data['confirm']:
            flash('Passwords do not match')
        elif any(u['username'] == data['username'] for u in users):
            flash('Username already exists')
        else:
            profile_pic = request.files.get('profile_pic')
            filename = None
            if profile_pic and allowed_file(profile_pic.filename, ALLOWED_IMAGE_EXTENSIONS):
                filename = secure_filename(str(uuid.uuid4()) + '_' + profile_pic.filename)
                profile_pic.save(os.path.join(PROFILE_PICS_FOLDER, filename))
            users.append({
                'username': data['username'],
                'password': generate_password_hash(data['password']),
                'profile_pic': filename,
                'sweetcoins': 0,
                'is_premium': False
            })
            return redirect(url_for('login'))
    return render_template('register.html', countries=COUNTRIES)

@app.route('/register_model', methods=['GET', 'POST'])
def register_model():
    error = None
    if request.method == 'POST':
        data = request.form
        username = data.get('username')
        password = data.get('password')
        confirm = data.get('confirm')

        if password != confirm:
            error = "Passwords do not match."
        elif any(u['username'] == username for u in users):
            error = "Username already exists."
        else:
            profile_pic = request.files.get('profile_pic')
            id_card = request.files.get('id_card')
            selfie = request.files.get('selfie')

            if not (profile_pic and id_card and selfie):
                error = "All required files must be uploaded."
            else:
                def save_file(file):
                    filename = secure_filename(str(uuid.uuid4()) + '_' + file.filename)
                    file.save(os.path.join(PROFILE_PICS_FOLDER, filename))
                    return filename

                profile_pic_filename = save_file(profile_pic)
                id_card_filename = save_file(id_card)
                selfie_filename = save_file(selfie)

                users.append({
                    'username': username,
                    'email': data.get('email'),
                    'phone': data.get('phone'),
                    'gender': data.get('gender'),
                    'age': data.get('age'),
                    'country': data.get('country'),
                    'telegram': data.get('telegram'),
                    'bio': data.get('bio'),
                    'password': generate_password_hash(password),
                    'profile_pic': profile_pic_filename,
                    'id_card': id_card_filename,
                    'selfie': selfie_filename,
                    'sweetcoins': 0,
                    'is_premium': False,
                    'is_model': True
                })

                flash("Model application submitted successfully!")
                return redirect(url_for('login'))

    return render_template('register_model.html', countries=COUNTRIES, error=error)

@app.route('/model_login', methods=['GET', 'POST'])
def model_login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = next((u for u in users if u['username'] == username and u.get('is_model')), None)

        if user and check_password_hash(user['password'], password):
            session['username'] = user['username']
            session['is_model'] = True
            session['is_premium'] = user.get('is_premium', False)
            return redirect(url_for('channel', username=username))
        else:
            error = "Invalid credentials or not a model."

    return render_template('model_login.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uname = request.form['username']
        pwd = request.form['password']
        if uname == ADMIN_USERNAME and pwd == ADMIN_PASSWORD:
            session['username'] = uname
            session['is_admin'] = True
            return redirect(url_for('admin'))
        user = next((u for u in users if u['username'] == uname), None)
        if user and check_password_hash(user['password'], pwd):
            session['username'] = user['username']
            session['is_premium'] = user.get('is_premium', False)
            return redirect(url_for('home'))
        flash("Invalid credentials")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
def upload_video():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        data = request.form
        video_file = request.files.get('video')
        thumbnail = request.files.get('thumbnail')

        vid_filename = thumb_filename = None

        # Save video
        if video_file and allowed_file(video_file.filename, ALLOWED_VIDEO_EXTENSIONS):
            vid_filename = secure_filename(str(uuid.uuid4()) + '_' + video_file.filename)
            video_file.save(os.path.join(app.config['UPLOAD_FOLDER'], vid_filename))

        # Save thumbnail
        if thumbnail and allowed_file(thumbnail.filename, ALLOWED_IMAGE_EXTENSIONS):
            thumb_filename = secure_filename(str(uuid.uuid4()) + '_' + thumbnail.filename)
            thumbnail.save(os.path.join(app.config['UPLOAD_FOLDER'], thumb_filename))

        # Create Video object
        new_video = Video(
            title=data['title'],
            category=data['category'],
            country=data['country'],
            version=data['version'],
            uploader=session['username'],
            video_url=vid_filename,
            thumbnail_url=thumb_filename
        )

        db.session.add(new_video)
        db.session.commit()

        flash('✅ Video uploaded successfully!')
        return redirect(url_for('home'))

    return render_template('upload.html', categories=CATEGORIES, versions=VERSIONS, countries=COUNTRIES)

@app.route('/channel/<username>')
def channel(username):
    user = next((u for u in users if u['username'] == username), None)
    user_videos = [v for v in videos if v['username'] == username]
    return render_template('channel.html', user=user, videos=user_videos)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.context_processor
def inject_year():
    return {'current_year': datetime.utcnow().year}

@app.context_processor
def inject_globals():
    return {
        'CATEGORIES': CATEGORIES,
        'current_year': datetime.utcnow().year
    }

@app.route('/admin')
def admin():
    if 'username' not in session or session['username'] != 'Atauwu':
        return redirect(url_for('admin_login'))

    videos = Video.query.order_by(Video.id.desc()).all()
    total_users = User.query.count()  # ✅
    total_videos = len(videos)        # ✅
    total_wallet_balance = db.session.query(db.func.sum(User.wallet)).scalar() or 0  # ✅ Assuming "wallet" field exists

    return render_template(
        'admin.html',
        videos=videos,
        categories=CATEGORIES,
        countries=COUNTRIES,
        versions=VERSIONS,
        total_users=total_users,
        total_videos=total_videos,
        total_wallet_balance=total_wallet_balance
    )

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Compare with .env values securely
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD, password):
            session['username'] = username  # used by /admin route check
            return redirect(url_for('admin'))  # go to dashboard

        flash('Invalid credentials. Try again.', 'error')
        return redirect(url_for('admin_login'))

    return render_template('admin_login.html')

@app.context_processor
def inject_comments():
    return {'comments': comments}

@app.route('/tip/<model_username>')
def tip_model(model_username):
    # You can use this to render a tipping page or thank you message
    user = next((u for u in users if u['username'] == model_username), None)
    if not user:
        return "Model not found", 404
    return render_template("tip_model.html", user=user)

@app.route('/messenger')
def messenger():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('messenger.html')

@app.route("/watch/<int:video_id>")
def watch_video(video_id):
    video = Video.query.get_or_404(video_id)
    video.views += 1
    db.session.commit()
    return render_template("watch.html", video=video)

@app.route('/version/<version_name>')
def videos_by_version(version_name):
    videos = Video.query.filter_by(version=version_name).all()
    return render_template('version_videos.html', version=version_name, videos=videos)

@app.route('/admin/video/edit/<int:video_id>', methods=['GET', 'POST'])
def edit_video(video_id):
    video = Video.query.get_or_404(video_id)
    if request.method == 'POST':
        # Update fields from form data
        video.title = request.form['title']
        video.category = request.form['category']
        video.version = request.form['version']
        video.country = request.form['country']
        video.is_premium = request.form.get('is_premium') == 'True'
        # Optional: Update thumbnail, filename, tags etc.
        db.session.commit()
        flash('Video updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template(
        'edit_video.html',
        video=video,
        categories=CATEGORIES,
        versions=VERSIONS,
        countries=COUNTRIES
    )

@app.route('/admin/video/delete/<int:video_id>')
def delete_video(video_id):
    video = Video.query.get_or_404(video_id)
    db.session.delete(video)
    db.session.commit()
    flash('Video deleted successfully!', 'success')
    return redirect(url_for('admin'))

@app.route('/update_video/<int:video_id>', methods=['POST'])
def update_video(video_id):
    video = Video.query.get_or_404(video_id)

    video.title = request.form['title']
    video.category = request.form['category']
    video.country = request.form['country']
    video.version = request.form['version']

    db.session.commit()
    flash('✅ Video updated successfully!')
    return redirect(url_for('admin'))

@app.route('/like/<int:video_id>', methods=['POST'])
def like_video(video_id):
    video = Video.query.get_or_404(video_id)
    video.likes += 1
    db.session.commit()
    return redirect(url_for('watch_video', video_id=video_id))

@app.route('/comment/<int:video_id>', methods=['POST'])
def comment_video(video_id):
    video = Video.query.get_or_404(video_id)
    comment_text = request.form.get('comment')
    username = request.form.get('username', 'Anonymous')

    if comment_text:
        comment = Comment(video_id=video.id, username=username, text=comment_text)
        db.session.add(comment)
        db.session.commit()

    return redirect(url_for('watch_video', video_id=video.id))

@app.route('/livecam')
def livecam():
    return render_template('livecam.html')

@app.route('/game')
def game():
    return render_template('games.html')  # ✅ correct name

@app.route('/premium')
def premium():
    return render_template('premium.html')

@app.route('/chatroom')
def chatroom():
    return render_template('chatroom.html')

@app.before_first_request
def create_tables():
    db.create_all()

if __name__ == '__main__':
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(PROFILE_PICS_FOLDER, exist_ok=True)
    socketio.run(app, debug=True)

