import os

folders = [
    "bank_project",
    "bank_project/templates",
    "bank_project/static"
]

files = {
    "bank_project/app.py": "",
    "bank_project/models.py": "",
    "bank_project/db.sqlite3": "",
    "bank_project/requirements.txt": "",
    "bank_project/static/style.css": "",
    "bank_project/templates/layout.html": """<!doctype html>
<html>
<head><title>Bank</title></head>
<body>
    {% block content %}{% endblock %}
</body>
</html>""",
    "bank_project/templates/login.html": """{% extends "layout.html" %}
{% block content %}
<h2>Login</h2>
<form method="post">
  <input name="username" required>
  <input name="password" type="password" required>
  <button type="submit">Login</button>
</form>
{% endblock %}""",
    "bank_project/templates/register.html": """{% extends "layout.html" %}
{% block content %}
<h2>Register</h2>
<form method="post">
  <input name="username" required>
  <input name="password" type="password" required>
  <button type="submit">Register</button>
</form>
{% endblock %}""",
    "bank_project/templates/dashboard.html": """{% extends "layout.html" %}
{% block content %}
<h2>Welcome to your dashboard</h2>
<p>Balance: ${{ balance }}</p>
{% endblock %}"""
}

for folder in folders:
    os.makedirs(folder, exist_ok=True)

for path, content in files.items():
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

print("✅ Project folder created.")
