from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os, re, json
from urllib.parse import urlparse
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")
DB = os.path.join(os.path.dirname(__file__), "cybertechvision.db")

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
        con.execute("""CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
            scan_type TEXT, target TEXT, risk TEXT, score INTEGER,
            details TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
        con.execute("""CREATE TABLE IF NOT EXISTS quiz_results(
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
            score INTEGER, total INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")

def current_user():
    if "user_id" not in session:
        return None
    with db() as con:
        return con.execute("SELECT id,name,email FROM users WHERE id=?", (session["user_id"],)).fetchone()

def analyse_text(value, scan_type="URL"):
    """Educational prototype heuristics only; not a commercial security verdict."""
    text = (value or "").strip()
    low = text.lower()
    reasons = []
    score = 0
    if not text:
        return {"risk":"Unknown", "score":0, "reasons":["Please enter something to analyse."]}
    indicators = [
        (r"urgent|immediately|within 24 hours|suspended|verify now|act now", 20, "Uses urgency or pressure language"),
        (r"password|bank|upi|otp|credit.?card|login details", 20, "Requests sensitive account or payment information"),
        (r"bit\.ly|tinyurl|t\.co|is\.gd|cutt\.ly", 15, "Contains a URL-shortening service"),
        (r"free prize|you won|claim reward|lottery", 15, "Contains a prize or reward lure"),
        (r"download attachment|enable macros", 20, "Encourages risky attachment or macro activity"),
    ]
    for pattern, points, reason in indicators:
        if re.search(pattern, low):
            score += points
            reasons.append(reason)
    if scan_type in ("URL", "Website"):
        try:
            parsed = urlparse(text if "://" in text else "https://" + text)
            host = parsed.netloc.lower()
            if not host or "." not in host:
                score += 25; reasons.append("The address does not look like a normal public domain")
            if parsed.scheme != "https":
                score += 15; reasons.append("The URL does not use HTTPS")
            if "@" in text:
                score += 20; reasons.append("The URL contains an @ symbol that can disguise its destination")
            if re.search(r"\d+\.\d+\.\d+\.\d+", host):
                score += 20; reasons.append("The address uses an IP address instead of a domain name")
            if host.count("-") >= 3:
                score += 10; reasons.append("The domain contains several hyphens")
        except Exception:
            score += 20; reasons.append("The address could not be parsed normally")
    score = min(score, 100)
    risk = "High" if score >= 55 else "Medium" if score >= 25 else "Low"
    if not reasons:
        reasons = ["No obvious warning signs were found by this basic prototype check."]
    return {"risk":risk, "score":score, "reasons":reasons}

def save_scan(user, scan_type, target, result):
    if user:
        with db() as con:
            con.execute("INSERT INTO scans(user_id,scan_type,target,risk,score,details) VALUES(?,?,?,?,?,?)",
                        (user["id"], scan_type, target[:1000], result["risk"], result["score"],
                         json.dumps(result["reasons"])))

@app.context_processor
def inject_globals():
    return {"logged_user": current_user(), "year": datetime.now().year}

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/tools")
def tools():
    return render_template("tools.html")

@app.route("/scan/<kind>", methods=["GET", "POST"])
def scan(kind):
    labels = {"url":"URL Scanner", "email":"Email Checker", "qr":"QR Scanner", "website":"Website Checker"}
    if kind not in labels:
        return redirect(url_for("tools"))
    result = None
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        if kind == "qr":
            # Browser QR decoding is not included in this starter; accept pasted QR URL/text.
            scan_type = "QR"
        elif kind == "email":
            scan_type = "Email"
        elif kind == "website":
            scan_type = "Website"
        else:
            scan_type = "URL"
        result = analyse_text(target, scan_type)
        save_scan(current_user(), scan_type, target, result)
    return render_template("scan.html", kind=kind, page_title=labels[kind], result=result)

@app.route("/academy")
def academy():
    return render_template("academy.html")

@app.route("/lesson/<slug>")
def lesson(slug):
    lessons = {
        "phishing": ("Understanding Phishing", "Phishing is a social-engineering attack in which criminals try to trick people into sharing information or taking unsafe actions.", ["Check the sender and domain carefully.", "Do not share OTPs or passwords.", "Open important services using their official app or typed address."]),
        "passwords": ("Password & Account Security", "Strong, unique passwords and multi-factor authentication make account takeover harder.", ["Use a unique password for every important account.", "Use a reputable password manager.", "Enable multi-factor authentication where available."]),
        "browsing": ("Safe Web Browsing", "Safe browsing means checking destinations, downloads, permissions and browser warnings before interacting.", ["Keep your browser and operating system updated.", "Avoid unexpected downloads.", "Treat HTTPS as encryption, not proof that a site is trustworthy."])
    }
    item = lessons.get(slug)
    if not item:
        return redirect(url_for("academy"))
    return render_template("lesson.html", lesson=item)

@app.route("/quiz", methods=["GET", "POST"])
def quiz():
    questions = [
        {"q":"A message asks you to share an OTP to stop an account from being blocked. What should you do?",
         "opts":["Share it quickly","Never share it; verify through the official app/site","Forward it to friends"],"a":1},
        {"q":"What does HTTPS mainly indicate?","opts":["The site is guaranteed genuine","The connection is encrypted","The site has no malware"],"a":1},
        {"q":"What is a safer way to open your bank website?","opts":["Click an unexpected SMS link","Use a saved official bookmark or type the known address","Use any search advertisement"],"a":1}
    ]
    score = None
    if request.method == "POST":
        score = sum(1 for i,q in enumerate(questions) if request.form.get(f"q{i}") == str(q["a"]))
        user = current_user()
        if user:
            with db() as con:
                con.execute("INSERT INTO quiz_results(user_id,score,total) VALUES(?,?,?)", (user["id"], score, len(questions)))
    return render_template("quiz.html", questions=questions, score=score)

@app.route("/labs")
def labs():
    return render_template("labs.html")

@app.route("/labs/ctf")
def ctf():
    return render_template("ctf.html")

@app.route("/assistant", methods=["GET", "POST"])
def assistant():
    answer = None
    if request.method == "POST":
        q = request.form.get("question", "").lower()
        if any(x in q for x in ["phishing", "fake link", "suspicious link"]):
            answer = "Do not click the link or enter credentials. Check the sender and domain independently, and visit the service through its official app or known address."
        elif any(x in q for x in ["password", "otp", "2fa", "mfa"]):
            answer = "Use a unique password, enable multi-factor authentication, and never share an OTP or recovery code with anyone."
        elif any(x in q for x in ["virus", "malware", "infected"]):
            answer = "Disconnect from suspicious activity, avoid opening unknown files, run a scan with trusted security software, update your device, and seek professional help if sensitive accounts may be affected."
        else:
            answer = "I can provide basic guidance on phishing, passwords, malware and safe browsing. For urgent incidents, contact your device or account provider through its official support channel."
    return render_template("assistant.html", answer=answer)

@app.route("/threats")
def threats():
    # Sample educational feed; clearly labelled as demo data.
    items = [
        ("Phishing awareness", "Unexpected messages asking for OTPs or passwords", "High", "General advisory"),
        ("Fake delivery messages", "Check delivery links through the courier's official app", "Medium", "General advisory"),
        ("Software updates", "Install browser and operating-system security updates", "Low", "Best practice")
    ]
    return render_template("threats.html", items=items)

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact", methods=["GET", "POST"])
def contact():
    sent = request.method == "POST"
    if sent:
        flash("Thanks! This prototype contact form is a demo and has not sent an email.")
    return render_template("contact.html", sent=sent)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name","").strip()
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        if len(password) < 8:
            flash("Password must be at least 8 characters.")
        elif not name or not email:
            flash("Please complete all fields.")
        else:
            try:
                with db() as con:
                    cur = con.execute("INSERT INTO users(name,email,password) VALUES(?,?,?)",
                                      (name,email,generate_password_hash(password)))
                    session["user_id"] = cur.lastrowid
                return redirect(url_for("dashboard"))
            except sqlite3.IntegrityError:
                flash("An account with this email already exists.")
    return render_template("auth.html", mode="register")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        with db() as con:
            user = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            return redirect(url_for("dashboard"))
        flash("Invalid email or password.")
    return render_template("auth.html", mode="login")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        flash("Please log in to view your dashboard.")
        return redirect(url_for("login"))
    with db() as con:
        scans = con.execute("SELECT * FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 8", (user["id"],)).fetchall()
        totals = con.execute("SELECT COUNT(*) AS n FROM scans WHERE user_id=?", (user["id"],)).fetchone()["n"]
        quiz = con.execute("SELECT COUNT(*) AS n, COALESCE(AVG(score * 100.0 / total),0) AS avg FROM quiz_results WHERE user_id=?", (user["id"],)).fetchone()
    return render_template("dashboard.html", user=user, scans=scans, total_scans=totals, quiz_count=quiz["n"], quiz_avg=round(quiz["avg"]))

@app.route("/certificates")
def certificates():
    if not current_user():
        flash("Log in to view your learning certificates.")
        return redirect(url_for("login"))
    return render_template("certificates.html")

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    target = data.get("target","")
    kind = data.get("kind","URL")
    result = analyse_text(target, kind)
    save_scan(current_user(), kind, target, result)
    return jsonify(result)

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
    