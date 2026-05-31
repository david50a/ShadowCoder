"""
INTENTIONALLY VULNERABLE PYTHON APP — FOR SHADOWCODER TESTING ONLY
This file contains multiple real vulnerabilities for demonstration purposes.
DO NOT USE IN PRODUCTION.
"""

import os
import subprocess
import pickle
import hashlib
import sqlite3
import requests
import yaml

# ── Hardcoded credentials ──────────────────────────────────────────────────────
DB_PASSWORD = "supersecret123"
API_KEY = "sk-prod-abc123xyz789verylongkey"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"


# ── SQL Injection ─────────────────────────────────────────────────────────────
def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # VULNERABLE: string concatenation in SQL query
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()


def search_products(search_term):
    conn = sqlite3.connect("products.db")
    cursor = conn.cursor()
    # VULNERABLE: f-string SQL injection
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{search_term}%'")
    return cursor.fetchall()


# ── Command Injection ─────────────────────────────────────────────────────────
def ping_host(host):
    # VULNERABLE: shell=True with user input
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout.decode()


def run_report(report_name):
    # VULNERABLE: os.system with user input
    os.system(f"python reports/{report_name}.py")


# ── Unsafe Deserialization ────────────────────────────────────────────────────
def load_session(session_data: bytes):
    # VULNERABLE: pickle.loads on untrusted data
    return pickle.loads(session_data)


def parse_config(config_yaml: str):
    # VULNERABLE: yaml.load without SafeLoader
    return yaml.load(config_yaml)


# ── Path Traversal ────────────────────────────────────────────────────────────
def read_template(template_name):
    # VULNERABLE: open with user-controlled path
    with open(f"templates/{template_name}") as f:
        return f.read()


def download_file(filename):
    user_input = filename
    open(user_input)  # VULNERABLE: direct path traversal


# ── Code Injection ────────────────────────────────────────────────────────────
def calculate(expression):
    # VULNERABLE: eval with user input
    return eval(expression)


def run_script(code):
    # VULNERABLE: exec with user input
    exec(code)


# ── SSRF ──────────────────────────────────────────────────────────────────────
def fetch_avatar(url):
    # VULNERABLE: user-controlled URL in requests.get
    data = requests.get(url)
    return data.content


# ── Weak Cryptography ─────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    # VULNERABLE: MD5 for password hashing
    return hashlib.md5(password.encode()).hexdigest()


def verify_integrity(data: bytes) -> str:
    # VULNERABLE: SHA1 for integrity check
    return hashlib.sha1(data).hexdigest()


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(get_user("admin"))
    print(ping_host("google.com"))
    print(hash_password("password123"))
