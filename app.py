from sqlite3.dbapi2 import Timestamp
from flask import Flask, render_template, request, redirect, session, url_for, flash, g, send_file
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from io import StringIO, BytesIO
from datetime import datetime
import sqlite3
import os
import csv

load_dotenv()
app = Flask(__name__)
# Fallback if no .env
app.secret_key = os.getenv("SECRET_KEY", "fallback-secret")

bcrypt = Bcrypt(app)

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect("db.sqlite3")
        g.db.row_factory = sqlite3.Row
    return g.db

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
        password = request.form["password"]
        hashed = bcrypt.generate_password_hash(password).decode("utf-8")

        db = get_db()
        try:
            db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
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

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user and bcrypt.check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash("Logged in successfully.")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials.")
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    user_id = session["user_id"]

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
    if tx_type and tx_type != "all":
        query += " AND type = ?"
        params.append(tx_type)

    query += " ORDER BY timestamp ASC"
    rows = db.execute(query, params).fetchall()

    # Prepare chart data
    labels = []
    balances = []
    current_balance = 0

    for row in rows:
        if row["type"] == "deposit" or row["type"] == "transfer_in":
            current_balance += row["amount"]
        elif row["type"] == "withdraw" or row["type"] == "transfer_out":
            current_balance -= row["amount"]
        labels.append(row["timestamp"][:16])
        balances.append(current_balance)

    # Fetch user info
    user = db.execute("SELECT username, balance FROM users WHERE id = ?", (user_id,)).fetchone()

    # Notifications
    notifications = db.execute("SELECT * FROM notifications WHERE user_id = ? ORDER BY timestamp DESC", (user_id,)).fetchall()

    return render_template("dashboard.html",
                           username=user["username"],
                           balance=user["balance"],
                           labels=labels,
                           balances=balances,
                           notifications=notifications)

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

    # Write to a text stream first
    from io import StringIO
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

if __name__ == "__main__":
    app.run(debug=True)


