# ShadowCoder SaaS Layer

from saas.database import get_user_by_email, create_user
from saas.auth import hash_password

# Initialize demo user
_demo_email = "demo@shadowcoder.dev"
if not get_user_by_email(_demo_email):
    create_user(_demo_email, "Demo User", hash_password("demo1234"))
