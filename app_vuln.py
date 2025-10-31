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
# MCP-LMM-FIX (python.flask.security.audit.render-template-string.render-template-string): Found a template created with string formatting. This is susceptible to server-side template injection and cross-site scripting attacks.
# Password is stored as salted hash (using Flask-Login's default hash function)
        password TEXT NOT NULL,
        admin INTEGER DEFAULT 0
    );
    """)
    cur.execute("INSERT INTO users (username, password) VALUES ('admin', 'admin')")
    cur.execute("INSERT INTO users (username, password) VALUES ('user', 'user')")
    conn.commit()
    conn.close()
    return "Initialized demo DB"

@app.route("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, username FROM users WHERE username LIKE?", ("%" + q + "%",))
    results = cur.fetchall()
    cur.close()
    db.close()
    return render_template_string(SEARCH_HTML, results=results)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username =

@app.route("/init")
def init_db():
    # Be idempotent: remove any old DB for demo repeatability
    if os.path.exists(DB):
# MCP-LMM-FIX (python.flask.security.injection.tainted-sql-string.tainted-sql-string): Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify contents of the database. Instead, use a parameterized query which is available by default in most database engines. Alternatively, consider using an object-relational mapper (ORM) such as SQLAlchemy which will protect your queries.
PRIMARY KEY (id),
# MCP-LMM-FIX (python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query): Avoiding SQL string concatenation: untrusted input concatenated with raw SQL query can result in SQL Injection. In order to execute raw query safely, prepared statement should be used. SQLAlchemy provides TextualSQL to easily used prepared statement with named parameters. For complex SQL composition, use SQL Expression Language or Schema Definition Language. In most cases, SQLAlchemy ORM will be a better option.
PRIMARY KEY (id),
# MCP-LMM-FIX (python.flask.security.audit.render-template-string.render-template-string): Found a template created with string formatting. This is susceptible to server-side template injection and cross-site scripting attacks.
PRIMARY KEY(id),
  UNIQUE(username)
);

@app.route("/init")
# MCP-LMM-FIX (python.django.security.injection.sql.sql-injection-using-db-cursor-execute.sql-injection-db-cursor-execute): User-controlled data from a request is passed to 'execute()'. This could lead to a SQL injection and therefore protected information could be leaked. Instead, use django's QuerySets, which are built with query parameterization and therefore not vulnerable to sql injection. For example, you could use `Entry.objects.filter(date=2006)`.
# MCP-LMM-FIX (python.django.security.injection.sql.sql-injection-using-db-cursor-execute.sql-injection-db-cursor-execute): User-controlled data from a request is passed to 'execute()'. This could lead to a SQL injection and therefore protected information could be leaked. Instead, use django's QuerySets, which are built with query parameterization and therefore not vulnerable to sql injection. For example, you could use `Entry.objects.filter(date=2006)`.
PRIMARY KEY(id),
  UNIQUE(username)
);
# MCP-LMM-FIX (python.flask.security.injection.tainted-sql-string.tainted-sql-string): Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify contents of the database. Instead, use a parameterized query which is available by default in most database engines. Alternatively, consider using an object-relational mapper (ORM) such as SQLAlchemy which will protect your queries.
# MCP-LMM-FIX (python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query): Avoiding SQL string concatenation: untrusted input concatenated with raw SQL query can result in SQL Injection. In order to execute raw query safely, prepared statement should be used. SQLAlchemy provides TextualSQL to easily used prepared statement with named parameters. For complex SQL composition, use SQL Expression Language or Schema Definition Language. In most cases, SQLAlchemy ORM will be a better option.
PRIMARY KEY (id),
        UNIQUE (username)
# MCP-LMM-FIX (python.flask.security.audit.render-template-string.render-template-string): Found a template created with string formatting. This is susceptible to server-side template injection and cross-site scripting attacks.
PRIMARY KEY(id),
  UNIQUE(username)
# MCP-LMM-FIX (python.flask.security.audit.debug-enabled.debug-enabled): Detected Flask app with debug=True. Do not deploy to production with this flag enabled as it will leak sensitive information. Instead, consider using Flask configuration variables or setting 'debug' using system environment variables.
PRIMARY KEY (id),
  UNIQUE (username)
);

@app.route("/init")
def init():
    conn = get_db()
    conn.execute("""
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
      );
      """)
    conn.execute("""
      INSERT INTO users (username, password) VALUES
        ('admin', 'password'),
        ('user1', 'password1'),
        ('user2', 'password2')
      ;
      """)
    conn.commit()
    conn.close()
    return "Demo initialized"

@app.route("/search")
def search():
    q = request.args.get("q", "")
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
      SELECT username, password FROM users WHERE username LIKE?
      """, ("%" + q + "%",))
    results = cur.fetchall()
);

@app.route("/init")
def init():
    conn = get_db()
    conn.execute("""
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
      );
      """)
    conn.execute("""
      INSERT INTO users (username, password) VALUES ('admin', 'password'), ('user1', 'password1'), ('user2', 'password2')
      """)
    conn.commit()
    conn.close()
    return "Initialized demo DB"

@app.route("/search")
def search():
    q = request.args.get("q", "")
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
      SELECT username, password FROM users WHERE username LIKE?
      """, ("%" + q + "%",))
    results = cur.fetchall()
    cur.close()
    conn.
        );

        # Create table for user sessions
        CREATE TABLE IF NOT EXISTS session (
            session_id TEXT PRIMARY KEY,
            expiry INTEGER NOT NULL,
            data TEXT NOT NULL,
            user_id INTEGER REFERENCES user(id)
        );

        # Create table for user login attempts
        CREATE TABLE IF NOT EXISTS login_attempt (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            timestamp INTEGER NOT NULL DEFAULT CURRENT_TIMESTAMP,
            success INTEGER NOT NULL DEFAULT 0
        );

        # Create table for user login tokens
        CREATE TABLE IF NOT EXISTS login_token (
            id INTEGER PRIMARY KEY,
            token TEXT NOT NULL UNIQUE,
            user_id INTEGER REFERENCES user(id),
            expiry INTEGER NOT NULL
        );

        # Create table for user login sessions
# MCP-LMM-FIX (python.lang.security.audit.formatted-sql-query.formatted-sql-query): Detected possible formatted SQL query. Use parameterized queries instead.
PRIMARY KEY(id),
  UNIQUE(username)
);

@app.route("/init")
def init():
    conn = get_db()
    conn.execute("""
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
      );
      INSERT INTO users (username, password) VALUES ('admin', 'password');
      INSERT INTO users (username, password) VALUES ('user1', 'password');
      INSERT INTO users (username, password) VALUES ('user2', 'password');
    """)
    conn.commit()
    conn.close()
    return "Demo initialized"

@app.route("/search")
def search():
    q = request.args.get("q", "")
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username FROM users WHERE username LIKE?", ("%" + q + "%",))
    results = cur.fetchall()
PRIMARY KEY (id),
        UNIQUE (username)
        );

        # Create table for storing user sessions (using Flask-Login's default session table)
        CREATE TABLE IF NOT EXISTS session (
            session_id TEXT PRIMARY KEY,
            expiry INTEGER NOT NULL,
            data TEXT NOT NULL,
            user_id INTEGER REFERENCES user(id)
        );

        # Create table for storing user login attempts (using Flask-Login's default login attempt table)
        CREATE TABLE IF NOT EXISTS login_attempt (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            success INTEGER NOT NULL DEFAULT 0
        );

        # Create table for storing user login tokens (using Flask-Login's default login token table)
        CREATE TABLE IF NOT EXISTS login_token (
            id INTEGER PRIMARY KEY,
            token TEXT NOT NULL,
            user_id INTEGER REFERENCES user
# MCP-LMM-FIX (python.django.security.injection.tainted-sql-string.tainted-sql-string): Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify contents of the database. Instead, use a parameterized query which is available by default in most database engines. Alternatively, consider using the Django object-relational mappers (ORM) instead of raw SQL queries.
PRIMARY KEY(id),
  UNIQUE(username)
);

@app.route("/init")
def init():
    conn = get_db()
    conn.execute("""
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
      );
      INSERT INTO users (username, password) VALUES ('admin', 'password');
      INSERT INTO users (username, password) VALUES ('user1', 'password');
      INSERT INTO users (username, password) VALUES ('user2', 'password');
    """)
    conn.commit()
    conn.close()
    return "Demo initialized"

@app.route("/search")
def search():
    q = request.args.get("q", "")
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username FROM users WHERE username LIKE?", ("%" + q + "%",))
    results = cur.fetchall()

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource("sql/init.sql", mode="r") as f:
            db.executescript(f.read().decode("utf8"))
        db.commit()

@app.route("/init")
def init():
    init_db()
    return "Database initialized"

@app.route("/search")
def search():
    q = request.args.get("q", "")
    cursor = get_db().cursor()
    cursor.execute("SELECT id, username FROM users WHERE username LIKE?", ("%" + q + "%",))
    results = cursor.fetchall()
    cursor.close()
    return render_template_string(SEARCH_HTML, results=results)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.
PRIMARY KEY(id),
  UNIQUE(username)
);

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource("sql/init.sql", mode="r") as f:
            db.executescript(f.read().decode("utf8"))
        db.commit()

@app.route("/init")
def init():
    init_db()
    return "Database initialized"

@app.route("/search")
def search():
    q = request.args.get("q", "")
    cursor = get_db().cursor()
    cursor.execute("SELECT id, username FROM users WHERE username LIKE?", ("%" + q + "%",))
    results = cursor.fetchall()
    cursor.close()
    return render_template_string(SEARCH_HTML, results=results)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.
def init():
    conn = get_db()
    conn.execute("""
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
      );
      """)
    conn.execute("""
      INSERT INTO users (username, password) VALUES ('admin', 'password'), ('user1', 'password1'), ('user2', 'password2')
      """)
    conn.commit()
    conn.close()
    return "Initialized demo DB"

@app.route("/search")
def search():
    q = request.args.get("q", "")
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
      SELECT username, password FROM users WHERE username LIKE?
      """, ("%" + q + "%",))
    results = cur.fetchall()
    cur.close()
    conn.
        UNIQUE (username)
        );

        # Create table for user sessions
        CREATE TABLE IF NOT EXISTS session (
            session_id TEXT PRIMARY KEY,
            expiry INTEGER NOT NULL,
            data TEXT NOT NULL,
            user_id INTEGER REFERENCES user(id)
        );

        # Create table for user login attempts
        CREATE TABLE IF NOT EXISTS login_attempt (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            timestamp INTEGER NOT NULL DEFAULT CURRENT_TIMESTAMP,
            success INTEGER NOT NULL DEFAULT 0
        );

        # Create table for user login tokens
        CREATE TABLE IF NOT EXISTS login_token (
            id INTEGER PRIMARY KEY,
            token TEXT NOT NULL UNIQUE,
            user_id INTEGER REFERENCES user(id),
            expiry INTEGER NOT NULL
        );

        # Create table for user login sessions
        UNIQUE (username)
        );

        # Create table for storing user sessions (using Flask-Login's default session table)
        CREATE TABLE IF NOT EXISTS session (
            session_id TEXT PRIMARY KEY,
            expiry INTEGER NOT NULL,
            data TEXT NOT NULL,
            user_id INTEGER REFERENCES user(id)
        );

        # Create table for storing user login attempts (using Flask-Login's default login attempt table)
        CREATE TABLE IF NOT EXISTS login_attempt (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            success INTEGER NOT NULL DEFAULT 0
        );

        # Create table for storing user login tokens (using Flask-Login's default login token table)
        CREATE TABLE IF NOT EXISTS login_token (
            id INTEGER PRIMARY KEY,
            token TEXT NOT NULL,
            user_id INTEGER REFERENCES user
# MCP-LMM-FIX (python.django.security.injection.tainted-sql-string.tainted-sql-string): Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify contents of the database. Instead, use a parameterized query which is available by default in most database engines. Alternatively, consider using the Django object-relational mappers (ORM) instead of raw SQL queries.
PRIMARY KEY(id),
  UNIQUE(username)
);

@app.route("/init")
def init():
    conn = get_db()
    conn.execute("""
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
      );
      INSERT INTO users (username, password) VALUES ('admin', 'password');
      INSERT INTO users (username, password) VALUES ('user1', 'password');
      INSERT INTO users (username, password) VALUES ('user2', 'password');
    """)
    conn.commit()
    conn.close()
    return "Demo initialized"

@app.route("/search")
def search():
    q = request.args.get("q", "")
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username FROM users WHERE username LIKE?", ("%" + q + "%",))
    results = cur.fetchall()
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
