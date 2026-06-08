import os
import sqlite3
import subprocess
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse

app = FastAPI(title="Damn Vulnerable FastAPI App")

# Initialize a dummy vulnerable database
def init_db():
    conn = sqlite3.connect("test.db")
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    c.execute("INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'admin', 'supersecret123')")
    c.execute("INSERT OR IGNORE INTO users (id, username, password) VALUES (2, 'guest', 'guest')")
    conn.commit()
    conn.close()

init_db()

@app.get("/", response_class=HTMLResponse)
def index():
    return """
    <html>
        <head><title>Vulnerable App</title></head>
        <body>
            <h1>Welcome to the Vulnerable Test App</h1>
            <p>This is a purposely vulnerable application for testing ShadowCoder's Dynamic Scanner.</p>
            <ul>
                <li><a href="/login">Login Page (SQLi)</a></li>
                <li><a href="/ping">Ping Tool (Command Injection)</a></li>
                <li><a href="/fetch">Fetch URL (SSRF)</a></li>
            </ul>
        </body>
    </html>
    """

@app.get("/login", response_class=HTMLResponse)
def login_form():
    return """
    <html>
        <body>
            <h2>Login</h2>
            <form action="/login" method="post">
                Username: <input type="text" name="username"><br>
                Password: <input type="password" name="password"><br>
                <button type="submit">Login</button>
            </form>
        </body>
    </html>
    """

@app.post("/login")
def do_login(username: str = Form(...), password: str = Form(...)):
    # VULNERABILITY: SQL Injection
    conn = sqlite3.connect("test.db")
    c = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    try:
        c.execute(query)
        user = c.fetchone()
        if user:
            return {"status": "success", "user": user[1]}
        return {"status": "failed", "message": "Invalid credentials"}
    except Exception as e:
        return {"error": str(e)}

@app.get("/ping")
def ping_page():
    return HTMLResponse("""
    <html>
        <body>
            <h2>Network Ping Tool</h2>
            <form action="/ping/exec" method="get">
                IP to ping: <input type="text" name="ip" value="127.0.0.1">
                <button type="submit">Ping</button>
            </form>
        </body>
    </html>
    """)

@app.get("/ping/exec")
def execute_ping(ip: str):
    # VULNERABILITY: Command Injection
    # Windows ping command
    cmd = f"ping -n 1 {ip}"
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return {"output": output.decode(errors="ignore")}
    except subprocess.CalledProcessError as e:
        return {"error": e.output.decode(errors="ignore")}

@app.get("/fetch")
def fetch_url(url: str = "http://example.com"):
    # VULNERABILITY: SSRF (Server-Side Request Forgery)
    import urllib.request
    try:
        response = urllib.request.urlopen(url)
        return {"content": response.read().decode(errors="ignore")}
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8001)
