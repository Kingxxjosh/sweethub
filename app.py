from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import json
import requests

app = Flask(__name__)
app.secret_key = 'sweethub_secret'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///videos.db'
db = SQLAlchemy(app)
socketio = SocketIO(app)

PAYSTACK_SECRET_KEY = "sk_test_09a74040b27adc00d8d4d465b60e20c37d655f1f"
PAYSTACK_PUBLIC_KEY = "pk_test_1dc053fe95bf35500306a9c3cb32fb48be44dc20"

ALLOWED_VIDEO_EXTENSIONS = {'mp4'}
ALLOWED_IMAGE_EXTENSIONS = {'jpg', 'jpeg', 'png'}

CATEGORIES = [
    "Teen", "Ebony", "MILF", "Lesbian", "Amateur", "Big Ass", "POV", "Blonde", "Public", "Latina",
    "BBW", "Threesome", "Creampie", "Hardcore", "Mature", "Anal", "Rough", "Asian", "Interracial", "Feet",
    "Panties", "Squirt", "Outdoor", "Cumshot", "Roleplay", "Nurse", "College", "Vintage", "Massage", "Thick",
    "Strap-on", "Office", "Fisting", "Cuckold", "Gangbang", "DP", "Public Sex", "BDSM", "Toy", "Step Fantasy",
    "Premium"
]
COUNTRIES = ["Ghana", "USA", "UK", "India", "Germany", "France", "Japan", "Brazil", "Canada", "South Africa"]
VERSIONS = ["Straight", "Gay", "Trans"]
COMMENTS_FILE = 'comments.json'

def allowed_file(filename, allowed_set):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_set

def load_comments():
    if not os.path.exists(COMMENTS_FILE):
        return {}
    with open(COMMENTS_FILE, 'r') as f:
        return json.load(f)

def save_comments(data):
    with open(COMMENTS_FILE, 'w') as f:
        json.dump(data, f, indent=2)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    bio = db.Column(db.String(300), default="No bio yet")
    telegram = db.Column(db.String(100), default="")
    country = db.Column(db.String(100), default="")
    age = db.Column(db.Integer, default=18)
    gender = db.Column(db.String(50), default="Not specified")
    profile_pic = db.Column(db.String(200), default="default.png")

class Video(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    filename = db.Column(db.String(200), nullable=True)
    embed_code = db.Column(db.Text, nullable=True)
    thumbnail = db.Column(db.String(200), nullable=True)
    views = db.Column(db.Integer, default=0)
    duration = db.Column(db.String(50), default="4:20")
    likes = db.Column(db.Integer, default=0)
    category = db.Column(db.String(100), nullable=True)
    version = db.Column(db.String(50), nullable=True)
    country = db.Column(db.String(100), nullable=True)
    tags = db.Column(db.String(200), nullable=True)
    is_premium = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Model(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)

def get_flag(country_name):
    flags = {
        "Ghana": "🇬🇭", "USA": "🇺🇸", "UK": "🇬🇧", "India": "🇮🇳", "Germany": "🇩🇪",
        "France": "🇫🇷", "Japan": "🇯🇵", "Brazil": "🇧🇷", "Canada": "🇨🇦", "South Africa": "🇿🇦"
    }
    return flags.get(country_name, "🌍")

def get_flag_emoji(country):
    if not country: return ""
    code = country.strip().upper()
    return ''.join([chr(127397 + ord(c)) for c in code[:2]])

def verify_payment(reference):
    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"}
    url = f"https://api.paystack.co/transaction/verify/{reference}"
    response = requests.get(url, headers=headers)
    return response.json()

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/premium')
def premium():
    return render_template("premium.html", public_key=PAYSTACK_PUBLIC_KEY)

@app.route('/subscribe')
def subscribe():
    return render_template("subscribe.html", public_key=PAYSTACK_PUBLIC_KEY)

@app.route("/verify-payment/<reference>")
def verify_payment(reference):
    if not session.get("user_id"):
        return redirect(url_for("login"))

    headers = {
        "Authorization": "Bearer sk_test_09a74040b27adc00d8d4d465b60e20c37d655f1f"
    }
    url = f"https://api.paystack.co/transaction/verify/{reference}"
    response = requests.get(url, headers=headers)
    result = response.json()

    if result.get("data") and result["data"]["status"] == "success":
        user = User.query.get(session["user_id"])
        user.is_premium = True
        db.session.commit()
        return redirect(url_for("home"))
    else:
        return "❌ Payment verification failed"

@app.route('/tip/<int:video_id>')
def tip(video_id):
    video = Video.query.get_or_404(video_id)
    if video.category != "Premium":
        return "❌ Tipping is only available for Premium videos."
    return render_template("tip.html", public_key=PAYSTACK_PUBLIC_KEY, video=video)

@app.route('/thank_you')
def thank_you():
    return render_template("thank_you.html")

@app.route('/verify_payment')
def verify_payment_route():
    reference = request.args.get("reference")
    result = verify_payment(reference)
    if result.get("data", {}).get("status") == "success":
        return redirect(url_for("thank_you"))
    return "❌ Payment failed or not verified."

@app.route('/')
def home():
    videos = Video.query.order_by(Video.id.desc()).all()
    return render_template('index.html', videos=videos, categories=CATEGORIES, countries=COUNTRIES, versions=VERSIONS)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    results = Video.query.filter(Video.title.ilike(f"%{query}%")).all() if query else []
    return render_template('search_results.html', query=query, results=results, categories=CATEGORIES, countries=COUNTRIES, versions=VERSIONS)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['username'] = user.username
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            return redirect(url_for('home'))
        else:
            error = "❌ Invalid username or password"
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm = request.form['confirm']
        age = request.form.get('age', 18)
        gender = request.form.get('gender', 'Not specified')
        country = request.form.get('country', '')
        telegram = request.form.get('telegram', '')
        bio = request.form.get('bio', '')
        profile_pic = request.files.get('profile_pic')

        if password != confirm:
            error = "❌ Passwords do not match."
        elif User.query.filter_by(username=username).first():
            error = "❌ Username already exists."
        else:
            filename = "default.png"
            if profile_pic and profile_pic.filename != "":
                filename = secure_filename(profile_pic.filename)
                profile_pic.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            hashed_pw = generate_password_hash(password)
            new_user = User(
                username=username,
                password=hashed_pw,
                age=age,
                gender=gender,
                country=country,
                telegram=telegram,
                bio=bio,
                profile_pic=filename,
                is_admin=False
            )
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template("register.html", error=error)

@app.route('/register_model', methods=['GET', 'POST'])
def register_model():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if Model.query.filter_by(username=username).first():
            error = "❌ Model username already exists."
        else:
            hashed_pw = generate_password_hash(password)
            new_model = Model(username=username, password=hashed_pw)
            db.session.add(new_model)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template("register_model.html", error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/channel/<username>')
def channel(username):
    user = User.query.filter_by(username=username).first_or_404()
    videos = Video.query.filter_by(user_id=user.id).all()
    return render_template("channel.html", user=user, videos=videos)

@app.route('/messenger')
def messenger():
    return render_template("messenger.html")

@app.route('/watch/<int:video_id>')
def watch_video(video_id):
    video = Video.query.get_or_404(video_id)
    video.views += 1
    db.session.commit()
    comments_data = load_comments()
    comments = comments_data.get(str(video_id), [])
    recommended = Video.query.filter(Video.category == video.category, Video.id != video.id).limit(8).all()
    return render_template("watch.html", video=video, comments=comments, recommended=recommended)

@app.route('/like_video/<int:video_id>', methods=['POST'])
def like_video(video_id):
    video = Video.query.get_or_404(video_id)
    video.likes += 1
    db.session.commit()
    return redirect(url_for('watch_video', video_id=video.id))

@app.route('/comment/<int:video_id>', methods=['POST'], endpoint='add_comment')
def add_comment(video_id):
    if 'username' not in session:
        return redirect(url_for("login"))
    content = request.form.get("comment_text")
    if not content:
        return "❌ Comment cannot be empty"
    data = load_comments()
    if str(video_id) not in data:
        data[str(video_id)] = []
    data[str(video_id)].append({
        "username": session["username"],
        "text": content,
        "timestamp": datetime.utcnow().isoformat()
    })
    save_comments(data)
    return redirect(url_for("watch_video", video_id=video_id))

@app.route('/filter')
def filter_videos():
    category = request.args.get("category")
    filtered = Video.query.filter_by(category=category).all()
    return render_template("filter_results.html", videos=filtered, category=category)

@app.route('/admin')
def admin():
    if not session.get("is_admin"):
        return redirect(url_for("login"))
    videos = Video.query.order_by(Video.id.desc()).all()
    return render_template("admin.html", videos=videos, categories=CATEGORIES, countries=COUNTRIES, versions=VERSIONS)

@app.route('/upload', methods=['GET', 'POST'])
def upload_video():
    if not session.get("is_admin"):
        return redirect(url_for("login"))

    if request.method == 'POST':
        title = request.form['title']
        tags = request.form.get('tags', '')
        category = request.form.get('category')
        version = request.form.get('version')
        country = request.form.get('country')
        embed_code = request.form.get('embed_code', '').strip()
        is_premium = request.form.get('is_premium') == '1'

        video_file = request.files.get('video')
        thumbnail_file = request.files.get('thumbnail')

        filename = ""
        if embed_code:
            filename = embed_code
        elif video_file and allowed_file(video_file.filename, ALLOWED_VIDEO_EXTENSIONS):
            filename = secure_filename(video_file.filename)
            video_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            video_file.save(video_path)
        else:
            return "❌ Please upload a .mp4 file or provide a valid embed code."

        thumbnail_name = ""
        if thumbnail_file and allowed_file(thumbnail_file.filename, ALLOWED_IMAGE_EXTENSIONS):
            thumbnail_name = secure_filename(thumbnail_file.filename)
            thumbnail_file.save(os.path.join(app.config['UPLOAD_FOLDER'], thumbnail_name))

        new_video = Video(
            title=title,
            filename=filename,
            thumbnail=thumbnail_name,
            category=category,
            version=version,
            country=country,
            tags=tags,
            is_premium=is_premium,
            user_id=None
        )
        db.session.add(new_video)
        db.session.commit()
        return redirect(url_for('admin'))

    return render_template("upload.html", categories=CATEGORIES, countries=COUNTRIES, versions=VERSIONS)

@app.route('/delete_video/<int:video_id>')
def delete_video(video_id):
    if not session.get("is_admin"):
        return redirect(url_for("login"))
    video = Video.query.get_or_404(video_id)
    db.session.delete(video)
    db.session.commit()
    return redirect(url_for('admin'))

@app.route('/games')
def games():
    return render_template('games.html')

@app.route('/livecams')
def livecams():
    return render_template('livecams.html')

@app.route('/dislike_video/<int:video_id>', methods=['POST'])
def dislike_video(video_id):
    video = Video.query.get_or_404(video_id)
    if video.likes > 0:
        video.likes -= 1
        db.session.commit()
    return redirect(url_for('watch_video', video_id=video.id))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='atauwu').first():
            hashed_pw = generate_password_hash('SweetPass123')
            admin = User(username='atauwu', password=hashed_pw, is_admin=True, country="Ghana")
            db.session.add(admin)
            db.session.commit()
            print("✅ Admin created: atauwu / SweetPass123")
    socketio.run(app, debug=True)
