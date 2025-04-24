import streamlit as st
import os
import json
import base64
import datetime
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ===== File Paths =====
USERS_FILE = "users.json"
DATA_FILE = "secure_data.json"

# ===== Load or Initialize Users =====
if os.path.exists(USERS_FILE):
    with open(USERS_FILE, "r") as file:
        USER_CREDENTIALS = json.load(file)
else:
    USER_CREDENTIALS = {}

# ===== Load or Initialize Stored Data =====
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as file:
        stored_data = json.load(file)
else:
    stored_data = {}

# ===== Streamlit Session Setup =====
if "is_authenticated" not in st.session_state:
    st.session_state.is_authenticated = False
if "current_user" not in st.session_state:
    st.session_state.current_user = None
if "attempts" not in st.session_state:
    st.session_state.attempts = 0
if "lockout_until" not in st.session_state:
    st.session_state.lockout_until = None
if "page" not in st.session_state:
    st.session_state.page = "home"

# ===== Password Hashing Function =====
def hash_password(password):
    salt = b'static_salt_hahahaha'  # Can use random salt for next-level
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.b64encode(kdf.derive(password.encode())).decode()

# ===== Encryption Key Generator =====
def generate_key(passkey, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(passkey.encode()))

# ===== Insert Data =====
def insert_data(user, text, passkey):
    salt = os.urandom(16) # Random salt
    key = generate_key(passkey, salt)
    fernet = Fernet(key)
    encrypted_text = fernet.encrypt(text.encode()).decode()

    stored_data[user] = {
        "encrypted_text": encrypted_text,
        "salt": base64.b64encode(salt).decode()
    }

    with open(DATA_FILE, "w") as file:
        json.dump(stored_data, file)

# ===== Retrieve Data =====
def retrieve_data(user, passkey):
    if user not in stored_data:
        st.error("No data found for this user.")
        return

    if st.session_state.lockout_until:
        if datetime.datetime.now() < st.session_state.lockout_until:
            seconds = (st.session_state.lockout_until - datetime.datetime.now()).seconds
            st.warning(f"⏳ Locked! Try again in {seconds} seconds.")
            return
        else:
            st.session_state.lockout_until = None
            st.session_state.attempts = 0

    user_data = stored_data[user]
    salt = base64.b64decode(user_data["salt"])
    encrypted_text = user_data["encrypted_text"]

    try:
        key = generate_key(passkey, salt)
        fernet = Fernet(key)
        decrypted_text = fernet.decrypt(encrypted_text.encode()).decode()
        st.success("Decrypted Text: " + decrypted_text)
        st.session_state.attempts = 0
    except:
        st.session_state.attempts += 1
        st.error(f"❌ Incorrect passkey ({st.session_state.attempts}/3)")
        if st.session_state.attempts >= 3:
            st.session_state.lockout_until = datetime.datetime.now() + datetime.timedelta(minutes=1)
            st.session_state.is_authenticated = False
            st.session_state.page = "login"
            st.error("🚫 3 failed attempts — Locked for 1 minute.")

# ===== Register User =====
def register_user(username, password):
    if username in USER_CREDENTIALS:
        return False, "User already exists."
    USER_CREDENTIALS[username] = {
        "password": hash_password(password)
    }
    with open(USERS_FILE, "w") as file:
        json.dump(USER_CREDENTIALS, file)
    return True, "✅ Registration successful."

# ===== UI Streamlit Section =====
# ===== Login/Register Page =====
def login_page():
    st.title("🔐 Login or Register")

    tab1, tab2 = st.tabs(["Login", "Register"])

    with tab1:
        username = st.text_input("Username", key="login_user")
        password = st.text_input("Password", type="password", key="login_pass")
        if st.button("Login"):
            if username in USER_CREDENTIALS:
                hashed = hash_password(password)
                if USER_CREDENTIALS[username]["password"] == hashed:
                    st.session_state.is_authenticated = True
                    st.session_state.current_user = username
                    st.session_state.page = "home"
                    st.success("✅ Login successful")
                else:
                    st.error("❌ Incorrect password")
            else:
                st.error("❌ User not found")

    with tab2:
        new_user = st.text_input("New Username", key="reg_user")
        new_pass = st.text_input("New Password", type="password", key="reg_pass")
        if st.button("Register"):
            success, msg = register_user(new_user, new_pass)
            if success:
                st.success(msg)
                st.session_state.is_authenticated = True
                st.session_state.current_user = new_user
                st.session_state.page = "home"
            else:
                st.error(msg)

# ===== Home Page =====
def home_page():
    st.title("🏠 Welcome")
    st.write(f"👤 Logged in as: **{st.session_state.current_user}**")
    if st.button("🔐 Insert Data"):
        st.session_state.page = "insert"
    if st.button("🔓 Retrieve Data"):
        st.session_state.page = "retrieve"
    if st.button("🚪 Logout"):
        st.session_state.is_authenticated = False
        st.session_state.page = "login"

# ===== Insert_Data Page =====
def insert_page():
    st.title("🔐 Insert Secure Data")
    text = st.text_area("Enter text to encrypt")
    passkey = st.text_input("Enter passkey", type="password")
    if st.button("Encrypt & Save"):
        insert_data(st.session_state.current_user, text, passkey)
        st.success("✅ Data encrypted and saved")
    if st.button("🔙 Back to Home"):
        st.session_state.page = "home"

# ===== Retrieve_Data Page =====
def retrieve_page():
    st.title("🔓 Retrieve Data")
    passkey = st.text_input("Enter your passkey", type="password")
    if st.button("Decrypt"):
        retrieve_data(st.session_state.current_user, passkey)
    if st.button("🔙 Back to Home"):
        st.session_state.page = "home"

# ===== Router/Navigator =====
if not st.session_state.is_authenticated:
    login_page()
else:
    if st.session_state.page == "home":
        home_page()
    elif st.session_state.page == "insert":
        insert_page()
    elif st.session_state.page == "retrieve":
        retrieve_page()
    elif st.session_state.page == "login":
        login_page()
