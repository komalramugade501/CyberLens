import os
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import csv
import io
import random

load_dotenv()
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-only-change-this-key")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///cyberlens.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="user", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class LoginActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    username = db.Column(db.String(80), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    ip_address = db.Column(db.String(45))
    location = db.Column(db.String(100))
    device = db.Column(db.String(120))
    browser = db.Column(db.String(80))
    status = db.Column(db.String(20), nullable=False)
    is_suspicious = db.Column(db.Boolean, default=False, nullable=False)
    suspicious_reason = db.Column(db.String(255))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def detect_risk(username, location, timestamp, status):
    reasons = []
    recent_failures = LoginActivity.query.filter_by(username=username, status="Failed").filter(
        LoginActivity.timestamp >= timestamp - timedelta(minutes=10)
    ).count()
    if status == "Failed" and recent_failures >= 4:
        reasons.append("5 or more failed attempts within 10 minutes")
    previous_locations = [r[0] for r in db.session.query(LoginActivity.location).filter_by(username=username).distinct().all() if r[0]]
    if previous_locations and location not in previous_locations:
        reasons.append("Login from a new location")
    if timestamp.hour >= 0 and timestamp.hour < 5:
        reasons.append("Login during unusual hours (12 AM–5 AM)")
    return reasons

def log_activity(user, status, location="Satara, India", simulated=False):
    now = datetime.utcnow()
    reasons = detect_risk(user.username, location, now, status)
    activity = LoginActivity(
        user_id=user.id, username=user.username, timestamp=now,
        ip_address=request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1"),
        location=location, device=request.user_agent.platform or "Unknown device",
        browser=request.user_agent.browser or "Unknown browser", status=status,
        is_suspicious=bool(reasons), suspicious_reason="; ".join(reasons) if reasons else None
    )
    db.session.add(activity)
    db.session.commit()
    return activity

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if len(username) < 3 or "@" not in email or len(password) < 8:
            flash("Enter a username (3+ characters), valid email, and password (8+ characters).", "error")
        elif User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Username or email is already registered.", "error")
        else:
            user = User(username=username, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            log_activity(user, "Successful")
            flash("Account created successfully.", "success")
            return redirect(url_for("dashboard"))
    return render_template("auth.html", mode="register")

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        identity = request.form.get("identity", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter((User.username == identity) | (User.email == identity.lower())).first()
        if user and user.check_password(password):
            login_user(user)
            log_activity(user, "Successful")
            flash("Welcome back.", "success")
            return redirect(url_for("dashboard"))
        if user:
            log_activity(user, "Failed")
        flash("Invalid username/email or password.", "error")
    return render_template("auth.html", mode="login")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))

@app.route("/dashboard")
@login_required
def dashboard():
    records = LoginActivity.query.filter_by(user_id=current_user.id).order_by(LoginActivity.timestamp.desc()).limit(100).all()
    total = LoginActivity.query.filter_by(user_id=current_user.id).count()
    successful = LoginActivity.query.filter_by(user_id=current_user.id, status="Successful").count()
    failed = LoginActivity.query.filter_by(user_id=current_user.id, status="Failed").count()
    suspicious = LoginActivity.query.filter_by(user_id=current_user.id, is_suspicious=True).count()
    return render_template("dashboard.html", records=records, total=total, successful=successful, failed=failed, suspicious=suspicious)

@app.route("/simulate", methods=["POST"])
@login_required
def simulate():
    kind = request.form.get("kind")
    if kind == "failures":
        for _ in range(5):
            log_activity(current_user, "Failed", "Satara, India", True)
        flash("Five failed login events simulated. Check the activity table for alerts.", "error")
    elif kind == "new_location":
        log_activity(current_user, "Successful", "London, United Kingdom", True)
        flash("A login from a new location was simulated.", "error")
    elif kind == "unusual_time":
        fake_time = datetime.utcnow().replace(hour=2, minute=0)
        activity = LoginActivity(user_id=current_user.id, username=current_user.username,
            timestamp=fake_time, ip_address="198.51.100.24", location="Demo location",
            device="Demo device", browser="Demo browser", status="Successful",
            is_suspicious=True, suspicious_reason="Simulated login during unusual hours (12 AM–5 AM)")
        db.session.add(activity); db.session.commit()
        flash("An unusual-hours login event was simulated.", "error")
    else:
        flash("Unknown simulation option.", "error")
    return redirect(url_for("dashboard"))

@app.route("/export")
@login_required
def export_csv():
    records = LoginActivity.query.filter_by(user_id=current_user.id).order_by(LoginActivity.timestamp.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Timestamp", "Username", "Status", "Location", "IP Address", "Device", "Browser", "Suspicious", "Reason"])
    for r in records:
        writer.writerow([r.timestamp, r.username, r.status, r.location, r.ip_address, r.device, r.browser, r.is_suspicious, r.suspicious_reason or ""])
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=cyberlens_activity.csv"})

@app.route("/health")
def health():
    return jsonify(application="CyberLens", status="healthy")

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
