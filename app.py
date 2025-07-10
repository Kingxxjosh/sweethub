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
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200MB max upload
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///videos.db'
db = SQLAlchemy(app)
socketio = SocketIO(app)

PAYSTACK_SECRET_KEY = "sk_test_09a74040b27adc00d8d4d465b60e20c37d655f1f"
PAYSTACK_PUBLIC_KEY = "pk_test_1dc053fe95bf35500306a9c3cb32fb48be44dc20"

ALLOWED_VIDEO_EXTENSIONS = {'mp4'}
ALLOWED_IMAGE_EXTENSIONS = {'jpg', 'jpeg', 'png'}

CATEGORIES = ["Teen", "Ebony", "MILF", "Lesbian", "Amateur", "Big Ass", "POV", "Blonde", "Public", "Latina",
"BBW", "Threesome", "Creampie", "Hardcore", "Mature", "Anal", "Rough", "Asian", "Interracial", "Feet",
"Panties", "Squirt", "Outdoor", "Cumshot", "Roleplay", "Nurse", "College", "Vintage", "Massage", "Thick",
"Strap-on", "Office", "Fisting", "Cuckold", "Gangbang", "DP", "Public Sex", "BDSM", "Toy", "Step Fantasy", "Premium"]

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
    is_premium = db.Column(db.Boolean, default=False)
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

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/')
def home():
    videos = Video.query.order_by(Video.id.desc()).all()
    return render_template('index.html', videos=videos, categories=CATEGORIES, countries=COUNTRIES, versions=VERSIONS)

@app.route('/search')
def search():
    query = request.args.get('q', '').lower()
    filtered = Video.query.filter(Video.title.ilike(f'%{query}%')).all()
    return render_template('index.html', videos=filtered, categories=CATEGORIES, countries=COUNTRIES, versions=VERSIONS)

@app.route('/filter_videos')
def filter_videos():
    category = request.args.get('category')
    country = request.args.get('country')
    version = request.args.get('version')
    query = Video.query
    if category:
        query = query.filter_by(category=category)
    if country:
        query = query.filter_by(country=country)
    if version:
        query = query.filter_by(version=version)
    videos = query.all()
    return render_template('index.html', videos=videos, categories=CATEGORIES, countries=COUNTRIES, versions=VERSIONS)

@app.route('/watch/<int:video_id>')
def watch(video_id):
    video = Video.query.get_or_404(video_id)
    video.views += 1
    db.session.commit()
    comments = load_comments().get(str(video_id), [])
    return render_template('watch.html', video=video, comments=comments)

@app.route('/like/<int:video_id>', methods=['POST'])
def like(video_id):
    video = Video.query.get_or_404(video_id)
    video.likes += 1
    db.session.commit()
    return jsonify({'likes': video.likes})

@app.route('/comment/<int:video_id>', methods=['POST'])
def comment(video_id):
    comment = request.form['comment']
    user = session.get('username', 'Anonymous')
    comments = load_comments()
    comments.setdefault(str(video_id), []).append({'user': user, 'comment': comment, 'time': str(datetime.utcnow())})
    save_comments(comments)
    return redirect(url_for('watch', video_id=video_id))

@app.route('/subscribe')
def subscribe():
    return render_template("subscribe.html", public_key=PAYSTACK_PUBLIC_KEY)

@app.route("/verify-payment/<reference>")
def verify_payment(reference):
    if not session.get("user_id"):
        return redirect(url_for("login"))
    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"
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

@app.route('/register_user', methods=['GET', 'POST'])
def register_user():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        country = request.form.get('country', 'Ghana')
        if User.query.filter_by(username=username).first():
            return "❌ Username already taken"
        new_user = User(username=username, password=password, country=country)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register_user.html', countries=COUNTRIES)

@app.route('/register_model', methods=['GET', 'POST'])
def register_model():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        if Model.query.filter_by(username=username).first():
            return "❌ Username already exists"
        db.session.add(Model(username=username, password=password))
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register_model.html')

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
        filename = embed_code if embed_code else ""
        if video_file and allowed_file(video_file.filename, ALLOWED_VIDEO_EXTENSIONS):
            filename = secure_filename(video_file.filename)
            video_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        thumbnail_name = ""
        if thumbnail_file and allowed_file(thumbnail_file.filename, ALLOWED_IMAGE_EXTENSIONS):
            thumbnail_name = secure_filename(thumbnail_file.filename)
            thumbnail_file.save(os.path.join(app.config['UPLOAD_FOLDER'], thumbnail_name))
        new_video = Video(title=title, filename=filename, embed_code=embed_code, thumbnail=thumbnail_name,
                          category=category, version=version, country=country,
                          tags=tags, is_premium=is_premium)
        db.session.add(new_video)
        db.session.commit()
        return redirect(url_for('admin'))
    return render_template("upload.html", categories=CATEGORIES, countries=COUNTRIES, versions=VERSIONS)

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
        error = "❌ Invalid username or password"
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/delete_video/<int:video_id>')
def delete_video(video_id):
    if not session.get("is_admin"):
        return redirect(url_for("login"))
    video = Video.query.get_or_404(video_id)
    db.session.delete(video)
    db.session.commit()
    return redirect(url_for('admin'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='atauwu').first():
            admin = User(username='atauwu', password=generate_password_hash('SweetPass123'), is_admin=True, country="Ghana")
            db.session.add(admin)
            db.session.commit()
            print("✅ Admin created: atauwu / SweetPass123")
    socketio.run(app, debug=True)
