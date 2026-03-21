
app = Flask(__name__)

import os
from dotenv import load_dotenv
import hashlib

load_dotenv()  # PRECOGS_FIX: load environment variables from .env file
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")  # PRECOGS_FIX: use environment variable for AWS access key
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")  # PRECOGS_FIX: use environment variable for AWS secret key

# --- VULN 2: Weak crypto (MD5) for password hashing ---
def hash_password_md5(password: str) -> str:
    # Use a stronger hashing algorithm (e.g., SHA-256) for password hashing
    return hashlib.sha256(password.encode("utf-8")).hexdigest()  # PRECOGS_FIX: use SHA-256 instead of MD5 for hashing