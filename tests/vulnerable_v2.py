import os
from flask import request, render_template_string
from django.http import HttpResponse
import subprocess

def cmd_exec():
    # New command injection
    os.execv("/bin/bash", ["-c", request.args.get("cmd")])
    os.spawnv(os.P_WAIT, "/bin/bash", ["-c", request.args.get("cmd2")])

def xss_flask():
    user = request.args.get('user')
    # XSS via SSTI
    return render_template_string(f"Hello {user}")

def xss_django():
    user = request.args.get('user')
    # XSS via HttpResponse
    return HttpResponse(f"Hello {user}")

def high_entropy():
    # Should be flagged as High-entropy string (entropy > 4.5)
    SECRET = "AKIAIOSFODNN7EXAMPLEZZQ89JDIE12O3L"
    print(SECRET)
