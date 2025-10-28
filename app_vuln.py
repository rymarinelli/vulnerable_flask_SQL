# app_vuln.py
from flask import Flask, request, render_template_string, g
import sqlite3
import os

DB = "demo_vuln.db"
app = Flask(__name__)

# Simple templates (inline for demo)
INDEX_HTML = """
<h2>Demo: Vulnerable Flask App (SQL Injection)</h2>
<ul>
  <li><a href="/init">Initialize demo DB</a> (creates sample users)</li>
  <li><a href="/search">Search users (vulnerable)</a></li>
  <li><a href="/login">Login (vulnerable)</a></li>
</ul>
"""

SEARCH_HTML = """
<h3>Search users (vulnerable)</h3>
<form method="get" action="/search">
  <label>username contains: <input name="q" /></label>
  <button type="submit">Search</button>
</form>
{% if results is not none %}
  <h4>Results</h4>
  <ul>
  {% for r in results %}
    <li>{{ r[0] }} — {{ r[1] }}</li>
  {% endfor %}
  </ul>
{% endif %}
<p><a href="/">Back</a></p>
"""

LOGIN_HTML = """
<h3>Login (vulnerable)</h3>
<form method="post" action="/login">
  <label>username: <input name="username" /></label><br/>
  <label>password: <input name="password" type="password" /></label><br/>
  <button type="submit">Login</button>
</form>
{% if user is not none %}
  {% if user %}
    <p style="color:green">Login OK — user id {{ user[0] }} username {{ user[1] }}</p>
  {% else %}
    <p style="color:red">Login failed</p>
  {% endif %}
{% endif %}
<p><a href="/">Back</a></p>
"""

def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = sqlite3.connect(DB)
        g._db = db
    return db

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()

@app.route("/")
def index():
    return render_template_string(INDEX_HTML)

@app.route("/init")
def init_db():
    # Be idempotent: remove any old DB for demo repeatability
    if os.path.exists(DB):
        os.remove(DB)
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.executescript("""
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    );
    INSERT INTO users (username, password) VALUES
      ('alice', 'alicepass'),
      ('bob', 'bobpass'),
      ('charlie', 'charliepass');
    """)
    conn.commit()
    conn.close()
    return "<p>Initialized demo DB with sample users.</p><p><a href='/'>Back</a></p>"

@app.route("/search")
def search():
    q = request.args.get("q", "")
    results = None
    if q:
        db = get_db()
        cur = db.cursor()
        # ---- VULNERABLE: concatenating user input into SQL ----
        sql = "SELECT id, username FROM users WHERE username LIKE '%" + q + "%';"
        # For the demo we intentionally execute this unsafe SQL
        cur.execute(sql)
        results = cur.fetchall()
    return render_template_string(SEARCH_HTML, results=results)

@app.route("/login", methods=["GET", "POST"])
def login():
    user = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()
        cur = db.cursor()
        # ---- VULNERABLE: direct string formatting into SQL ----
        sql = f"SELECT id, username FROM users WHERE username = '{username}' AND password = '{password}' LIMIT 1;"
        cur.execute(sql)
        row = cur.fetchone()
        user = row
    return render_template_string(LOGIN_HTML, user=user)

if __name__ == "__main__":
    app.run(debug=True)
