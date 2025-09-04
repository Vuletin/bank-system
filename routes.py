from flask import render_template, redirect, url_for, session, request, flash
from extensions import db, bcrypt
from models import User, Transaction, Notification, Note
from flask import render_template, request, redirect, session, url_for, flash, send_file
from extensions import bcrypt, mail
from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer
from models import Note, db, User, Transaction, Notification
from functools import wraps
from datetime import datetime, timezone
from io import StringIO, BytesIO
import csv

# --- Routes ---
def register_routes(app):
    @app.route("/")
    def home():
        if "user_id" in session:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    # Utilities
    def is_valid_date(date_str):
        try:
            datetime.strptime(date_str, "%Y-%m-%d")
            return True
        except ValueError:
            return False

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

    @app.route("/logout")
    def logout():
        session.clear()
        flash("You have been logged out.")
        return redirect(url_for("login"))

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
            user.email = email.lower()
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
                timestamp=datetime.now(timezone.utc)
            )
            db.session.add(transaction)

        db.session.commit()
        flash(f"Balance for user #{user_id} reset to ${new_balance:.2f}")
        return redirect(url_for("dashboard"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip().lower()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password")

            # Validation
            if not username or not email or not password:
                flash("All fields are required.")
                return render_template("register.html")

            if User.query.filter_by(username=username).first():
                flash("Username already exists.")
                return render_template("register.html")

            if User.query.filter_by(email=email).first():
                flash("Email already exists.")
                return render_template("register.html")

            # Register new user
            hashed = bcrypt.generate_password_hash(password).decode("utf-8")
            user = User(username=username, email=email, password=hashed)
            db.session.add(user)
            db.session.commit()
            flash("Registration successful! Please log in.")
            return redirect(url_for("login"))

        return render_template("register.html")

    def recreate_admin():
        existing = User.query.filter_by(username="admin").first()
        if existing:
            print("✅ Admin user already exists.")
            return

        password = "sava"
        hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")

        new_admin = User(
            username="admin",
            email="admin@example.com",
            password=hashed_pw,
            is_admin=True
        )
        db.session.add(new_admin)
        db.session.commit()
        print("✅ Admin user created: admin / sava")

    @app.route("/whoami")
    def whoami():
        return f"User: {session.get('username')} | ID: {session.get('user_id')} | Admin: {session.get('is_admin')}"

    @app.route("/login", methods=["GET", "POST"])
    def login():
        try:
            if request.method == "POST":
                username = request.form.get("username", "").strip().lower()
                password = request.form.get("password", "")

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

        types = ["deposit", "withdraw", "transfer_in", "transfer_out"]

        # Prepare data for charts
        labels = []
        type_data = {t: [] for t in types}
        date_totals = {}

        for row in rows:
            if row.timestamp:
                ts = row.timestamp.strftime("%Y-%m-%d %H:%M")
            else:
                ts = "Unknown"

            if ts not in date_totals:
                date_totals[ts] = {t: 0 for t in types}

            if row.type in types:
                date_totals[ts][row.type] += float(row.amount or 0)

        sorted_dates = sorted(date_totals.keys())
        labels = sorted_dates
        for t in types:
            type_data[t] = [round(date_totals[date].get(t, 0), 2) for date in sorted_dates]

        net_data = []
        net_labels = []
        running_total = 0

        for row in rows:
            amt = float(row.amount or 0)

            if row.type in ["deposit", "transfer_in"]:
                running_total += amt
            elif row.type in ["withdraw", "transfer_out"]:
                running_total -= amt

            # ✅ Check timestamp here too
            if row.timestamp:
                ts = row.timestamp.strftime("%Y-%m-%d %H:%M")
            else:
                ts = "Unknown"

            net_labels.append(ts)
            net_data.append(round(running_total, 2))

        # Totals
        totals = {t: 0 for t in types}
        for row in rows:
            if row.type in types:
                totals[row.type] += float(row.amount or 0)

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
            totals=totals,
            notifications=notifications,
            net_data=net_data,
            net_labels=net_labels,
            labels=labels,
            type_data=type_data
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
        recipient_username = request.form.get("recipient", "").strip().lower()
        try:
            amount = float(request.form.get("amount", 0))
        except ValueError:
            flash("Invalid amount.")
            return redirect(url_for("dashboard"))
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
            end_datetime = end_date + " 23:59:59"
            query = query.filter(Transaction.timestamp <= end_datetime)
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

        note = Note(user_id=session["user_id"], content=content)
        db.session.add(note)
        db.session.commit()
        flash("Note added.")
        return redirect(url_for("dashboard"))

    @app.route("/export_csv")
    def export_csv():
        if "user_id" not in session:
            return redirect(url_for("login"))

        user_id = session.get("user_id")

        start_date = request.args.get("start_date")
        end_date = request.args.get("end_date")
        tx_type = request.args.get("type")

        query = "SELECT type, amount, timestamp, note FROM transactions WHERE user_id = ?"
        params = [user_id]

        # Use SQLAlchemy ORM instead of raw SQL
        query_obj = Transaction.query.filter_by(user_id=user_id)

        if start_date and is_valid_date(start_date):
            query_obj = query_obj.filter(Transaction.timestamp >= start_date)
        if end_date and is_valid_date(end_date):
            query_obj = query_obj.filter(Transaction.timestamp <= end_date + " 23:59:59")
        if tx_type:
            query_obj = query_obj.filter_by(type=tx_type)

        query_obj = query_obj.order_by(Transaction.timestamp.desc())
        transactions = query_obj.all()

        # Write to a text stream first
        string_io = StringIO()
        writer = csv.writer(string_io)
        writer.writerow(["Type", "Amount", "Timestamp", "Note"])
        for tx in transactions:
            writer.writerow([tx.type, tx.amount, tx.timestamp, tx.note])

        # Encode to binary stream
        mem = BytesIO()
        mem.write(string_io.getvalue().encode("utf-8"))
        mem.seek(0)

        # Add today's date to the filename
        timestamp = datetime.now().strftime("%Y-%m-%d")

        # filename = f"transactions_{timestamp}.csv"
        
        return send_file(mem,
                        as_attachment=True,
                        download_name="transactions.csv",
                        mimetype="text/csv")

    def sync_user_balance(user_id):
        user = User.query.get(user_id)
        if not user:
            return

        recorded_balance = float(user.balance)

        transactions = Transaction.query.filter_by(user_id=user_id).all()

        calculated_balance = 0
        for tx in transactions:
            amt = float(tx.amount or 0)
            if tx.type in ["deposit", "transfer_in"]:
                calculated_balance += amt
            elif tx.type in ["withdraw", "transfer_out"]:
                calculated_balance -= amt

        diff = round(recorded_balance - calculated_balance, 2)

        if diff != 0:
            tx_type = "deposit" if diff > 0 else "withdraw"
            correction = Transaction(
                user_id=user_id,
                type=tx_type,
                amount=abs(diff),
                note="Balance sync correction"
            )
            db.session.add(correction)
            db.session.commit()
            print(f"[SYNC] Corrected balance by {diff:.2f} for user ID {user_id}")

    @app.route("/admin/wipe_user/<int:user_id>", methods=["POST"])
    @admin_required
    def wipe_user(user_id):
        # Delete all transactions
        Transaction.query.filter_by(user_id=user_id).delete()

        # Reset balance
        user = User.query.get(user_id)
        if user:
            user.balance = 0.0

        db.session.commit()
        flash(f"All history wiped and balance reset for user #{user_id}")
        return redirect(url_for("admin_panel"))

    @app.route("/admin/sync_balances")
    @admin_required
    def sync_balances():
        users = User.query.with_entities(User.id).all()
        for user in users:
            sync_user_balance(user.id)
        flash("All user balances have been synchronized based on transactions.")
        return redirect(url_for("admin_panel"))

    @app.route("/healthz")
    def health_check():
        return "OK"

    @app.route("/make-admin/<int:user_id>")
    @admin_required
    def make_admin(user_id):
        user = User.query.get(user_id)
        if not user:
            flash("User not found.")
        elif user.is_admin:
            flash(f"✅ User {user.username} is already an admin.")
        else:
            user.is_admin = True
            db.session.commit()
            flash(f"✅ User {user.username} is now an admin.")
        return redirect(url_for("admin_panel"))

    @app.route("/promote-user/<string:username>")
    def promote_user(username):
        user = User.query.filter_by(username=username).first()
        if not user:
            return f"❌ User '{username}' not found."
        if user.is_admin:
            return f"✅ User '{username}' is already an admin."
        user.is_admin = True
        db.session.commit()
        return f"✅ User '{username}' promoted to admin."

    @app.route("/debug-users")
    def debug_users():
        users = User.query.all()
        if not users:
            return "❌ No users found."
        return "<br>".join([f"{u.id}: {u.username} | {u.email} | Admin: {u.is_admin}" for u in users])