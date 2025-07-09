from sqlite3.dbapi2 import Timestamp
from flask import Flask, render_template, request, redirect, session, url_for, flash, g, send_file
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from io import StringIO, BytesIO
from datetime import datetime
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from functools import wraps
from io import StringIO
import logging
import sqlite3
import os
import csv

app = Flask(__name__)

load_dotenv()

app.config['DEBUG'] = True
app.config['PROPAGATE_EXCEPTIONS'] = True
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

print("MAIL_USERNAME:", app.config['MAIL_USERNAME'])
print("MAIL_PASSWORD:", app.config['MAIL_PASSWORD'])  # Will print as None or masked

mail = Mail(app)

bcrypt = Bcrypt(app)

logging.basicConfig(level=logging.DEBUG)

def generate_reset_token(email):
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return s.dumps(email, salt='password-reset-salt')

def verify_reset_token(token, max_age=3600):  # 1 hour expiry
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

def init_db():
    if not os.path.exists("db.sqlite3"):
        with sqlite3.connect("db.sqlite3") as db:
            with open("schema.sql", "r") as f:
                db.executescript(f.read())
        print("✅ db.sqlite3 created from schema.sql")

init_db()

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect("db.sqlite3")
        g.db.row_factory = sqlite3.Row
    return g.db

@app.route("/admin")
@admin_required
def admin_panel():
    db = get_db()
    users = db.execute("SELECT id, username, email, balance, is_banned FROM users").fetchall()
    return render_template("admin.html", users=users)

@app.route("/admin/delete/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    if session["user_id"] == user_id:
        flash("You can't delete yourself.")
        return redirect(url_for("admin_panel"))

    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    flash(f"User {user_id} deleted.")
    return redirect(url_for("admin_panel"))

@app.route("/admin/edit/<int:user_id>", methods=["GET", "POST"])
@admin_required
def edit_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if request.method == "POST":
        username = request.form["username"]
        email = request.form.get("email")

        db.execute("UPDATE users SET username = ?, email = ? WHERE id = ?",
                   (username, email, user_id))

        db.commit()
        flash("User updated.")
        return redirect(url_for("admin_panel"))

    return render_template("edit_user.html", user=user)

@app.route("/ban_user/<int:user_id>", methods=["POST"])
@admin_required
def ban_user(user_id):
    if session["user_id"] == user_id:
        flash("You can't ban yourself.")
        return redirect(url_for("admin_panel"))

    db = get_db()
    user = db.execute("SELECT is_banned FROM users WHERE id = ?", (user_id,)).fetchone()

    if user is not None:
        new_status = 0 if user["is_banned"] else 1
        db.execute("UPDATE users SET is_banned = ? WHERE id = ?", (new_status, user_id))
        db.commit()

    return redirect(url_for("admin_panel"))

@app.route("/toggle_admin/<int:user_id>", methods=["POST"])
@admin_required
def toggle_admin(user_id):
    db = get_db()
    user = db.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,)).fetchone()

    if user:
        new_status = 0 if user["is_admin"] else 1
        db.execute("UPDATE users SET is_admin = ? WHERE id = ?", (new_status, user_id))
        db.commit()
        flash("Admin privileges updated.")
    return redirect(url_for("admin_panel"))

@app.route("/admin/reset_balance", methods=["POST"])
def admin_reset_balance():
    if "user_id" not in session or session["user_id"] != 1:
        flash("Unauthorized.")
        return redirect(url_for("dashboard"))

    user_id = int(request.form["user_id"])
    new_balance = float(request.form["amount"])

    db = get_db()
    user = db.execute("SELECT balance FROM users WHERE id = ?", (user_id,)).fetchone()

    if not user:
        flash("User not found.")
        return redirect(url_for("dashboard"))

    old_balance = float(user["balance"])
    delta = round(new_balance - old_balance, 2)

    db.execute("UPDATE users SET balance = ? WHERE id = ?", (new_balance, user_id))

    if delta != 0:
        tx_type = "deposit" if delta > 0 else "withdraw"
        db.execute("""
            INSERT INTO transactions (user_id, type, amount, note, timestamp)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (user_id, tx_type, abs(delta), "Admin reset"))

    db.commit()
    flash(f"Balance for user #{user_id} reset to ${new_balance:.2f}")
    return redirect(url_for("dashboard"))

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

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

        db = get_db()
        try:
            db.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", 
                    (username, hashed, email))
            db.commit()
            flash("Registration successful. Please log in.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already exists.")
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("login"))

def recreate_admin():
    db = get_db()
    password = "sava"  # Or whatever password you want
    hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")

    db.execute(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
        ("admin", hashed_pw, 1),
    )
    db.commit()
    print("✅ Admin user recreated with username: admin and password: admin123")

@app.route("/whoami")
def whoami():
    return f"Logged in as {session.get('username')} | Admin: {session.get('is_admin')}"

@app.route("/login", methods=["GET", "POST"])
def login():
    try:
        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")

            db = get_db()
            user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

            if user:
                if user["is_banned"]:
                    flash("Account banned.")
                    return redirect(url_for("login"))

                if bcrypt.check_password_hash(user["password"], password):
                    session["user_id"] = user["id"]
                    session["username"] = user["username"]
                    session["is_admin"] = user["is_admin"]
                    flash("Logged in successfully.")
                    return redirect(url_for("dashboard"))
                else:
                    print("⚠️ Password mismatch for user:", user["username"])
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
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
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

        db = get_db()

        db.execute("UPDATE users SET password = ? WHERE email = ?", (hashed, email))
        db.commit()
        flash('Your password has been updated!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

# Receives token from URL
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    user_id = session.get("user_id")

    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    tx_type = request.args.get("type")  # Optional

    # Build base query
    query = "SELECT * FROM transactions WHERE user_id = ?"
    params = [user_id]

    if start_date:
        query += " AND timestamp >= ?"
        params.append(start_date)
    if end_date:
        query += " AND timestamp <= ?"
        params.append(end_date + " 23:59:59")
    if tx_type and tx_type != "all" and tx_type != "":
        query += " AND type = ?"
        params.append(tx_type)

    query += " ORDER BY timestamp ASC"
    rows = db.execute(query, params).fetchall()

    # Prepare chart data by type
    labels = []
    types = ["deposit", "withdraw", "transfer_in", "transfer_out"]
    type_data = {t: [] for t in types}
    timestamps_seen = set()

    # Collect unique timestamps (minute precision)
    for row in rows:
        ts = row["timestamp"][:16]  # "YYYY-MM-DD HH:MM"
        if ts not in timestamps_seen:
            labels.append(ts)
            timestamps_seen.add(ts)

    # Initialize zeros for each type per timestamp
    for t in types:
        type_data[t] = [0] * len(labels)

    # Fill type_data arrays
    for row in rows:
        ts = row["timestamp"][:16]
        idx = labels.index(ts)
        tx_t = row["type"]
        if tx_t in types:
            type_data[tx_t][idx] += float(row["amount"] or 0)

    # Calculate totals
    totals = {t: 0 for t in types}
    for row in rows:
        tx_t = row["type"]
        if tx_t in types:
            totals[tx_t] += float(row["amount"] or 0)

    # Calculate net total over time for the second chart
    net_data = []
    net_labels = []
    running_total = 0

    # Use rows ordered by timestamp, update running total per transaction
    for row in rows:
        amt = float(row["amount"] or 0)
        tx_t = row["type"]
        if tx_t in ["deposit", "transfer_in"]:
            running_total += amt
        elif tx_t in ["withdraw", "transfer_out"]:
            running_total -= amt
        # Append timestamp and running total after each transaction
        net_labels.append(row["timestamp"][:16])
        net_data.append(round(running_total, 2))

    # Fetch user info
    user = db.execute("SELECT username, balance FROM users WHERE id = ?", (user_id,)).fetchone()

    notifications = db.execute("""
        SELECT * FROM notifications
        WHERE user_id = ?
        ORDER BY timestamp DESC
        LIMIT 5
    """, (user_id,)).fetchall()

    # If user is None
    if user is None:
        flash("User not found. Please log in again.")
        session.clear()
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        username=user["username"],
        balance=user["balance"],
        labels=labels,
        type_data=type_data,
        totals=totals,
        notifications=notifications,
        net_data=net_data,
        net_labels=net_labels
    )

@app.route("/traFnsaction", methods=["POST"])
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

    db = get_db()
    user = db.execute("SELECT balance FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    balance = user["balance"] if user else 0

    if action == "deposit":
        new_balance = balance + amount
        flash(f"Deposited ${amount:.2f}!")
    elif action == "withdraw":
        if amount > balance:
            flash("Insufficient funds.")
            return redirect(url_for("dashboard"))
        new_balance = balance - amount
        flash(f"Withdrew ${amount:.2f}.")
    else:
        flash("Invalid action.")
        return redirect(url_for("dashboard"))

    db.execute("UPDATE users SET balance = ? WHERE id = ?", (new_balance, session["user_id"]))
    db.execute("""
        INSERT INTO transactions (user_id, type, amount, note)
        VALUES (?, ?, ?, ?)
    """, (session["user_id"], action, amount, note))
    db.commit()
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

    db = get_db()

    # Check if recipient exists
    recipient = db.execute("SELECT id FROM users WHERE username = ?", (recipient_username,)).fetchone()
    if not recipient:
        flash("Recipient user not found.")
        return redirect(url_for("dashboard"))

    recipient_id = recipient["id"]

    if recipient_id == sender_id:
        flash("You can't transfer money to yourself.")
        return redirect(url_for("dashboard"))

    # Get sender balance
    sender = db.execute("SELECT balance FROM users WHERE id = ?", (sender_id,)).fetchone()
    if sender["balance"] < amount:
        flash("Insufficient funds.")
        return redirect(url_for("dashboard"))

    # Perform the transfer
    db.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, sender_id))
    db.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, recipient_id))

    # Log transaction for sender
    db.execute("""
        INSERT INTO transactions (user_id, type, amount, note, recipient_id)
        VALUES (?, 'transfer_out', ?, ?, ?)
    """, (sender_id, amount, note, recipient_id))

    # Log transaction for recipient
    db.execute("""
        INSERT INTO transactions (user_id, type, amount, note, recipient_id)
        VALUES (?, 'transfer_in', ?, ?, ?)
    """, (recipient_id, amount, note, sender_id))

    # Notification when user receives money
    sender = db.execute("SELECT username FROM users WHERE id = ?", (sender_id,)).fetchone()
    sender_username = sender["username"]

    sender_message = f"You sent ${amount:.2f} to {recipient_username}."
    db.execute("INSERT INTO notifications (user_id, message) VALUES (?, ?)", (sender_id, sender_message))

    message = f"You received ${amount:.2f} from {sender_username}."
    db.execute("INSERT INTO notifications (user_id, message) VALUES (?, ?)", (recipient_id, message))

    db.commit()
    return redirect(url_for("dashboard"))

@app.route("/history")
def history():
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    user_id = session["user_id"]

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

def sync_user_balance(user_id):
    db = get_db()
    user = db.execute("SELECT balance FROM users WHERE id = ?", (user_id,)).fetchone()
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