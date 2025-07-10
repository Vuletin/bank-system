from flask import Flask, render_template, request, redirect, session, url_for, flash, send_file
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv
from functools import wraps
from datetime import datetime
import os
import csv
import logging
from io import StringIO, BytesIO
from models import db, User, Transaction, Notification, Note

load_dotenv()

app = Flask(__name__)

# Initialize the database
with app.app_context():
    db.create_all()

# Configuration
app.config['DEBUG'] = True
app.config['PROPAGATE_EXCEPTIONS'] = True
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# Logging
logging.basicConfig(level=logging.DEBUG)
print("MAIL_USERNAME:", app.config['MAIL_USERNAME'])
print("MAIL_PASSWORD:", app.config['MAIL_PASSWORD'])

# Extensions
bcrypt = Bcrypt(app)
mail = Mail(app)
db.init_app(app)

# Create tables
with app.app_context():
    db.create_all()

# Utilities
def generate_reset_token(email):
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return s.dumps(email, salt='password-reset-salt')

def verify_reset_token(token, max_age=3600):
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        return s.loads(token, salt='password-reset-salt', max_age=max_age)
    except Exception:
        return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("is_admin"):
            flash("Admin access only.")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated_function

# Admin Routes
@app.route("/admin")
@admin_required
def admin_panel():
    users = User.query.with_entities(User.id, User.username, User.email, User.is_banned).all()
    return render_template("admin.html", users=users)

@app.route("/admin/delete/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    if session["user_id"] == user_id:
        flash("You can't delete yourself.")
        return redirect(url_for("admin_panel"))

    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash(f"User {user_id} deleted.")
    else:
        flash("User not found.")

    return redirect(url_for("admin_panel"))

@app.route("/admin/edit/<int:user_id>", methods=["GET", "POST"])
@admin_required
def edit_user(user_id):
    user = User.query.get(user_id)

    if not user:
        flash("User not found.")
        return redirect(url_for("admin_panel"))

    if request.method == "POST":
        username = request.form["username"]
        email = request.form.get("email")
        user.username = username
        user.email = email
        db.session.commit()
        flash("User updated.")
        return redirect(url_for("admin_panel"))

    return render_template("edit_user.html", user=user)
@app.route("/ban_user/<int:user_id>", methods=["POST"])
@admin_required
def ban_user(user_id):
    if session["user_id"] == user_id:
        flash("You can't ban yourself.")
        return redirect(url_for("admin_panel"))

    user = User.query.get(user_id)
    if user:
        user.is_banned = not user.is_banned
        db.session.commit()
        flash("User ban status updated.")
    else:
        flash("User not found.")

    return redirect(url_for("admin_panel"))

@app.route("/toggle_admin/<int:user_id>", methods=["POST"])
@admin_required
def toggle_admin(user_id):
    user = User.query.get(user_id)
    if user:
        user.is_admin = not user.is_admin
        db.session.commit()
        flash("Admin privileges updated.")
    else:
        flash("User not found.")
    return redirect(url_for("admin_panel"))

@app.route("/admin/reset_balance", methods=["POST"])
def admin_reset_balance():
    if "user_id" not in session or session["user_id"] != 1:
        flash("Unauthorized.")
        return redirect(url_for("dashboard"))

    user_id = int(request.form["user_id"])
    new_balance = float(request.form["amount"])

    user = User.query.get(user_id)
    if not user:
        flash("User not found.")
        return redirect(url_for("dashboard"))

    old_balance = getattr(user, "balance", 0.0)
    delta = round(new_balance - old_balance, 2)
    user.balance = new_balance

    if delta != 0:
        tx_type = "deposit" if delta > 0 else "withdraw"
        transaction = Transaction(
            user_id=user_id,
            type=tx_type,
            amount=abs(delta),
            note="Admin reset",
            timestamp=datetime.utcnow()
        )
        db.session.add(transaction)

    db.session.commit()
    flash(f"Balance for user #{user_id} reset to ${new_balance:.2f}")
    return redirect(url_for("dashboard"))

@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form.get("password")
        email = request.form["email"]
        hashed = bcrypt.generate_password_hash(password).decode("utf-8")

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists.")
            return render_template("register.html")

        user = User(username=username, password=hashed, email=email)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful. Please log in.")
        return redirect(url_for("login"))

    return render_template("register.html")
@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("login"))


def recreate_admin():
    password = "sava"  # Or whatever password you want
    hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")

    new_admin = User(username="admin", password=hashed_pw, is_admin=True)
    db.session.add(new_admin)
    db.session.commit()
    print("✅ Admin user recreated with username: admin and password: sava")


@app.route("/whoami")
def whoami():
    return f"Logged in as {session.get('username')} | Admin: {session.get('is_admin')}"


@app.route("/login", methods=["GET", "POST"])
def login():
    try:
        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")

            user = User.query.filter_by(username=username).first()

            if user:
                if user.is_banned:
                    flash("Account banned.")
                    return redirect(url_for("login"))

                if bcrypt.check_password_hash(user.password, password):
                    session["user_id"] = user.id
                    session["username"] = user.username
                    session["is_admin"] = user.is_admin
                    flash("Logged in successfully.")
                    return redirect(url_for("dashboard"))
                else:
                    print("⚠️ Password mismatch for user:", user.username)
                    flash("Invalid password.")
            else:
                print("⚠️ User not found for username:", username)
                flash("User not found.")

            return redirect(url_for("login"))

        return render_template("login.html")

    except Exception as e:
        print("Login Error:", e)
        return "Internal Server Error", 500


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = generate_reset_token(email)
            link = url_for('reset_password', token=token, _external=True)
            msg = Message("Password Reset Request", recipients=[email])
            msg.body = f"Click the link to reset your password:\n{link}\nThis link expires in 1 hour."
            mail.send(msg)
            flash("Password reset link sent to your email.", "info")
        else:
            flash("Email not found.", "danger")

    return render_template("forgot_password.html")


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = verify_reset_token(token)
    if not email:
        flash('Reset link is invalid or expired.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        hashed = bcrypt.generate_password_hash(new_password).decode('utf-8')

        user = User.query.filter_by(email=email).first()
        if user:
            user.password = hashed
            db.session.commit()
            flash('Your password has been updated!', 'success')
            return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session.get("user_id")

    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    tx_type = request.args.get("type")  # Optional

    # Build query dynamically
    query = Transaction.query.filter_by(user_id=user_id)

    if start_date:
        query = query.filter(Transaction.timestamp >= start_date)
    if end_date:
        query = query.filter(Transaction.timestamp <= end_date + " 23:59:59")
    if tx_type and tx_type != "all" and tx_type != "":
        query = query.filter_by(type=tx_type)

    query = query.order_by(Transaction.timestamp.asc())
    rows = query.all()

    # Prepare chart data by type
    labels = []
    types = ["deposit", "withdraw", "transfer_in", "transfer_out"]
    type_data = {t: [] for t in types}
    timestamps_seen = set()

    for row in rows:
        ts = row.timestamp.strftime("%Y-%m-%d %H:%M")
        if ts not in timestamps_seen:
            labels.append(ts)
            timestamps_seen.add(ts)

    for t in types:
        type_data[t] = [0] * len(labels)

    for row in rows:
        ts = row.timestamp.strftime("%Y-%m-%d %H:%M")
        idx = labels.index(ts)
        if row.type in types:
            type_data[row.type][idx] += float(row.amount or 0)

    # Totals
    totals = {t: 0 for t in types}
    for row in rows:
        if row.type in types:
            totals[row.type] += float(row.amount or 0)

    # Net total over time
    net_data = []
    net_labels = []
    running_total = 0
    for row in rows:
        amt = float(row.amount or 0)
        if row.type in ["deposit", "transfer_in"]:
            running_total += amt
        elif row.type in ["withdraw", "transfer_out"]:
            running_total -= amt
        net_labels.append(row.timestamp.strftime("%Y-%m-%d %H:%M"))
        net_data.append(round(running_total, 2))

    user = User.query.get(user_id)
    if not user:
        flash("User not found. Please log in again.")
        session.clear()
        return redirect(url_for("login"))

    notifications = Notification.query.filter_by(user_id=user_id)\
        .order_by(Notification.timestamp.desc())\
        .limit(5).all()

    return render_template(
        "dashboard.html",
        username=user.username,
        balance=user.balance,
        labels=labels,
        type_data=type_data,
        totals=totals,
        notifications=notifications,
        net_data=net_data,
        net_labels=net_labels
    )
@app.route("/transaction", methods=["POST"])
def transaction():
    if "user_id" not in session:
        return redirect(url_for("login"))

    action = request.form["action"]
    try:
        amount = float(request.form["amount"])
    except ValueError:
        flash("Invalid amount.")
        return redirect(url_for("dashboard"))

    if amount <= 0:
        flash("Amount must be greater than zero.")
        return redirect(url_for("dashboard"))
    
    note = request.form.get("note", "")

    user = User.query.get(session["user_id"])
    if not user:
        flash("User not found.")
        return redirect(url_for("dashboard"))

    if action == "deposit":
        user.balance += amount
        flash(f"Deposited ${amount:.2f}!")
    elif action == "withdraw":
        if amount > user.balance:
            flash("Insufficient funds.")
            return redirect(url_for("dashboard"))
        user.balance -= amount
        flash(f"Withdrew ${amount:.2f}.")
    else:
        flash("Invalid action.")
        return redirect(url_for("dashboard"))

    tx = Transaction(
        user_id=user.id,
        type=action,
        amount=amount,
        note=note
    )
    db.session.add(tx)
    db.session.commit()
    return redirect(url_for("dashboard"))


@app.route("/transfer", methods=["POST"])
def transfer():
    if "user_id" not in session:
        return redirect(url_for("login"))

    sender_id = session["user_id"]
    recipient_username = request.form.get("recipient")
    amount = float(request.form.get("amount", 0))
    note = request.form.get("note", "")

    if amount <= 0:
        flash("Amount must be greater than zero.")
        return redirect(url_for("dashboard"))

    sender = User.query.get(sender_id)
    recipient = User.query.filter_by(username=recipient_username).first()

    if not recipient:
        flash("Recipient user not found.")
        return redirect(url_for("dashboard"))

    if recipient.id == sender_id:
        flash("You can't transfer money to yourself.")
        return redirect(url_for("dashboard"))

    if sender.balance < amount:
        flash("Insufficient funds.")
        return redirect(url_for("dashboard"))

    # Perform the transfer
    sender.balance -= amount
    recipient.balance += amount

    db.session.add_all([
        Transaction(user_id=sender.id, type="transfer_out", amount=amount, note=note, recipient_id=recipient.id),
        Transaction(user_id=recipient.id, type="transfer_in", amount=amount, note=note, recipient_id=sender.id),
        Notification(user_id=sender.id, message=f"You sent ${amount:.2f} to {recipient.username}."),
        Notification(user_id=recipient.id, message=f"You received ${amount:.2f} from {sender.username}.")
    ])

    db.session.commit()
    return redirect(url_for("dashboard"))


@app.route("/history")
def history():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    tx_type = request.args.get("type")

    query = Transaction.query.filter_by(user_id=user_id)

    if start_date:
        query = query.filter(Transaction.timestamp >= start_date)
    if end_date:
        query = query.filter(Transaction.timestamp <= end_date + " 23:59:59")
    if tx_type:
        query = query.filter_by(type=tx_type)

    transactions = query.order_by(Transaction.timestamp.desc()).all()

    return render_template("history.html", transactions=transactions)

@app.route("/add_note", methods=["POST"])
def add_note():
    if "user_id" not in session:
        return redirect(url_for("login"))

    content = request.form.get("content", "").strip()
    if not content:
        flash("Note cannot be empty.")
        return redirect(url_for("dashboard"))

    db = get_db()
    db.execute("INSERT INTO notes (user_id, content) VALUES (?, ?)", (session["user_id"], content))
    db.commit()
    flash("Note added.")
    return redirect(url_for("dashboard"))

@app.route("/export_csv")
def export_csv():
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    user_id = session.get("user_id")

    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    tx_type = request.args.get("type")

    query = "SELECT type, amount, timestamp, note FROM transactions WHERE user_id = ?"
    params = [user_id]

    if start_date:
        query += " AND timestamp >= ?"
        params.append(start_date)
    if end_date:
        query += " AND timestamp <= ?"
        params.append(end_date + " 23:59:59")
    if tx_type:
        query += " AND type = ?"
        params.append(tx_type)

    query += " ORDER BY timestamp DESC"
    transactions = db.execute(query, params).fetchall()

    # Write to a text stream first
    string_io = StringIO()
    writer = csv.writer(string_io)
    writer.writerow(["Type", "Amount", "Timestamp", "Note"])
    for tx in transactions:
        writer.writerow([tx["type"], tx["amount"], tx["timestamp"], tx["note"]])

    # Encode to binary stream
    mem = BytesIO()
    mem.write(string_io.getvalue().encode("utf-8"))
    mem.seek(0)

    # Add today's date to the filename
    timestamp = datetime.now().strftime("%Y-%m-%d")

    filename = f"transactions_{timestamp}.csv"
    
    return send_file(mem,
                     as_attachment=True,
                     download_name="transactions.csv",
                     mimetype="text/csv")

@app.route("/debug-users")
def debug_users():
    db = get_db()
    users = db.execute("SELECT id, username, email, is_admin FROM users").fetchall()
    return "<br>".join([f"{u['id']}: {u['username']} | {u['email']} | Admin: {u['is_admin']}" for u in users])

def get_db():
    return db.session

def sync_user_balance(user_id):
    db = get_db()
    user = db.execute("SELECT balance FROM users WHERE id = %s", (user_id,)).fetchone()
    if not user:
        return

    recorded_balance = float(user["balance"])
    rows = db.execute("SELECT type, amount FROM transactions WHERE user_id = ?", (user_id,)).fetchall()

    # Recalculate actual balance from history
    calculated_balance = 0
    for row in rows:
        amt = float(row["amount"] or 0)
        if row["type"] in ["deposit", "transfer_in"]:
            calculated_balance += amt
        elif row["type"] in ["withdraw", "transfer_out"]:
            calculated_balance -= amt

    # Check for mismatch
    diff = round(recorded_balance - calculated_balance, 2)
    if diff != 0:
        tx_type = "deposit" if diff > 0 else "withdraw"
        db.execute("""
            INSERT INTO transactions (user_id, type, amount, note, timestamp)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (user_id, tx_type, abs(diff), "Balance sync correction"))
        db.commit()

@app.route("/admin/wipe_user/<int:user_id>", methods=["POST"])
@admin_required
def wipe_user(user_id):
    db = get_db()
    db.execute("DELETE FROM transactions WHERE user_id = ?", (user_id,))
    db.execute("UPDATE users SET balance = 0 WHERE id = ?", (user_id,))
    db.commit()
    flash(f"All history wiped and balance reset for user #{user_id}")
    return redirect(url_for("admin"))

@app.route("/admin/sync_balances")
@admin_required
def sync_balances():
    db = get_db()
    users = db.execute("SELECT id FROM users").fetchall()
    for user in users:
        sync_user_balance(user["id"])
    flash("All user balances have been synchronized based on transactions.")
    return redirect(url_for("admin_panel"))

@app.route("/healthz")
def health_check():
    return "OK"

if __name__ == "__main__":
    app.run(debug=True)