# 🏦 Bank System

A full-featured automated bank system written in Python using the Flask web framework. This project was developed as the final assignment for CS50, demonstrating understanding of backend web development, frontend templating, databases, user authentication, and secure financial logic. It simulates the core functionality of a basic online banking platform and includes an admin panel for user management and system maintenance.

##🎥 Video Demo


##🧠 Project Overview

This system allows users to register securely, manage their bank account, view their transaction history, and perform actions such as deposits, withdrawals, and transfers to other users. The app includes built-in error handling, input validation, and user-friendly feedback for a seamless experience.

Users can also view statistics about their finances through a graphical dashboard, with support for filtering by transaction type or date. Transaction history can be exported in CSV format, and charts (e.g. bar graphs or line graphs) can be exported as images for personal records.

The system was built with a focus on simplicity, security, and extensibility. While it is currently using SQLite for simplicity, the database layer is designed to be portable to PostgreSQL or MySQL in the future.

## 🚀 Features

User Authentication: Registration, login, logout, and password hashing with bcrypt.

Dashboard: Real-time display of account balance, recent activity, and charts.

Deposits/Withdrawals: User can add or withdraw funds, with optional comments. Withdrawals are restricted if funds are insufficient.

Transfers: Users can transfer funds to other users by entering their username. The action is logged from both the sender and receiver perspectives (transfer_out and transfer_in).

Transaction History: All financial actions are logged and shown in a filterable table. Filters include date, transaction type, and keyword. Users can export their transaction history to a .csv file.

Graphical Analytics: Bar and line charts provide insights into transaction trends, with options to export visualizations as PNG or CSV.

Admin Panel: Admins can manage users (edit/delete/ban), monitor suspicious activity, and reset balances.

Notifications System: Users receive alerts (coming soon) for important events (e.g. successful transfers).

Security: Secure password hashing (bcrypt), input validation, CSRF protection via Flask forms.

Database: Data is stored in a normalized SQLite database, with relational tables for users, transactions, and session tracking.

## 📂 File Structure and Explanation

File/Folder	Description
app.py	Main Flask app entry point. Handles routing, session management, and database interactions.
templates/	Contains HTML templates used to render dynamic pages using Jinja2 (e.g. dashboard, login, register).
database.db	SQLite database file (auto-created if missing). Contains users and transactions tables.
.env	Stores secret keys and environment variables (e.g., Flask SECRET_KEY).
requirements.txt	Lists all necessary Python packages. Used for pip install -r requirements.txt.
README.md	This file. Describes the project, functionality, and usage.

## ⚙️ Setup Instructions⚙️ Setup Instructions

Clone the repository:

1. Clone the repository:
git clone https://github.com/Vuletin/bank-system.git
cd bank-system
Install dependencies:

2. Install dependencies:
pip install -r requirements.txt
Create a .env file:

3. Create a .env file:
SECRET_KEY=your_secret_key_here
Run the app:

4. Run the app:
flask run
Open http://127.0.0.1:5000 in your browser.

##🔧 Design Decisions

Several key design decisions were made during development:

Transactions are split into types: Instead of one generic transaction type, the database distinguishes between deposit, withdraw, transfer_in, and transfer_out. This makes querying, filtering, and charting simpler and more accurate.

Separation of logic and presentation: Templates are kept free from business logic to ensure maintainability. All core logic lives in Python.

Password hashing with bcrypt: To protect user passwords in case of a database breach. No plain text or reversible encryption is used.

Reusable chart rendering: Charts can be reused and exported without frontend JavaScript by using server-side rendering.

Admin-only actions are protected via decorators and role checks: Ensuring that only admins can access sensitive pages like the admin panel.

Clean session handling: Session data is minimal and server-side checks are performed to prevent session hijacking or privilege escalation.

##🔮 Future Improvements

This app is built to be modular and extensible. Planned features include:

Budget planning tools for users to manage spending and savings goals.

OAuth2 integration (e.g., Google, GitHub login).

Docker containerization for deployment ease.

Transition from SQLite to PostgreSQL for better scalability.

Real-time notifications via websockets or email.

Mobile-friendly responsive layout.

##✅ Summary

This project showcases full-stack web development with a focus on secure financial operations, clean UI, and practical data management. It includes most features you'd expect from an entry-level online banking interface and can be extended into a full SaaS-style platform. Whether you're checking your balance or auditing a year’s worth of transactions, this system handles it all with clarity and control.

I developed this as a way to challenge myself with realistic functionality and system design, and I’m proud of how far it has come.

1. Clone the repo  
```bash
git clone https://github.com/Vuletin/bank-system.git
