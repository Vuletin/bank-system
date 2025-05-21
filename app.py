from flask import Flask, render_template, request, redirect, session, url_for, flash, g
from flask_bcrypt import Bcrypt
import sqlite3
import os
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
# Fallback if no .env
app.secret_key = os.getenv("SECRET_KEY", "fallback-secret")

if __name__ == "__main__":
    app.run(debug=True)

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
    user = db.execute("SELECT username, balance FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    return render_template("dashboard.html", balance=user["balance"])

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
    db.execute("INSERT INTO transactions (user_id, type, amount) VALUES (?, ?, ?)", 
        (session["user_id"], action, amount))

    db.commit()
    return redirect(url_for("dashboard"))

@app.route("/history")
def history():
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    transactions = db.execute(
        "SELECT type, amount, timestamp FROM transactions WHERE user_id = ? ORDER BY timestamp DESC",
        (session["user_id"],)
    ).fetchall()

    return render_template("history.html", transactions=transactions)

