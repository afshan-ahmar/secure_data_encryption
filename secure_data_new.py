import streamlit as st
from cryptography.fernet import Fernet
import base64
import hashlib

# ---- Custom CSS for Colorful UI ----
st.set_page_config(page_title="Secure In-Memory Vault", layout="centered")

st.markdown("""
    <style>
        .main {
            background-color: #f5f7fa;
        }
        .stButton>button {
            color: white;
            background-color: #4CAF50;
            border-radius: 8px;
            padding: 0.5em 1em;
        }
        .stTextInput>div>div>input {
            border: 2px solid #4CAF50;
            border-radius: 8px;
        }
        .stTextArea>div>textarea {
            border: 2px solid #2196F3;
            border-radius: 8px;
        }
    </style>
""", unsafe_allow_html=True)



# ---- In-Memory Storage ----
if 'data_store' not in st.session_state:
    st.session_state.data_store = {}

if 'authenticated' not in st.session_state:
    st.session_state.authenticated = True

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

# ---- Utility Functions ----
def generate_key(passkey: str) -> bytes:
    # Derive key from passkey using SHA256
    return base64.urlsafe_b64encode(hashlib.sha256(passkey.encode()).digest())

def encrypt_data(data: str, passkey: str) -> bytes:
    key = generate_key(passkey)
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())

def decrypt_data(token: bytes, passkey: str) -> str:
    key = generate_key(passkey)
    fernet = Fernet(key)
    return fernet.decrypt(token).decode()

# ---- Login Page ----
def login_page():
    st.title("🔐 Reauthorization Required")
    st.warning("Too many failed attempts. Please reauthorize to continue.")
    username = st.text_input("Enter Username", key="login_user")
    password = st.text_input("Enter Password", type="password", key="login_pass")
    if st.button("Login"):
        if username == "admin" and password == "password123":
            st.success("Logged in successfully.")
            st.session_state.failed_attempts = 0
            st.session_state.authenticated = True
        else:
            st.error("Invalid credentials.")

# ---- Main App ----
def main_app():
    st.title("🔒 Secure Vault")
    st.subheader("Store & Retrieve Data Securely - In Memory")

    st.markdown("---")
    menu = st.radio("Select Option", ["Store Data", "Retrieve Data"], horizontal=True)

    if menu == "Store Data":
        key = st.text_input("🔑 Set Your Unique Passkey", type="password")
        data = st.text_area("📝 Enter Data to Store")

        if st.button("🔐 Encrypt & Store"):
            if key and data:
                encrypted = encrypt_data(data, key)
                st.session_state.data_store[key] = encrypted
                st.success("✅ Data encrypted and stored in memory!")
            else:
                st.error("Both passkey and data are required.")

    elif menu == "Retrieve Data":
        key = st.text_input("🔑 Enter Your Passkey to Decrypt", type="password")

        if st.button("🔓 Decrypt & Retrieve"):
            if key:
                encrypted_data = st.session_state.data_store.get(key)
                if encrypted_data:
                    try:
                        decrypted = decrypt_data(encrypted_data, key)
                        st.success("✅ Data Retrieved Successfully!")
                        st.text_area("📄 Your Decrypted Data", value=decrypted, height=200)
                        st.session_state.failed_attempts = 0  # Reset on success
                    except Exception:
                        st.session_state.failed_attempts += 1
                        st.error("❌ Incorrect passkey.")
                else:
                    st.session_state.failed_attempts += 1
                    st.error("❌ No data found for this passkey.")
            else:
                st.error("Please enter your passkey.")

    # Show failed attempts
    if st.session_state.failed_attempts > 0:
        st.warning(f"Failed attempts: {st.session_state.failed_attempts}/3")

    # Lockout after 3 attempts
    if st.session_state.failed_attempts >= 3:
        st.session_state.authenticated = False

# ---- Run App ----
if st.session_state.authenticated:
    main_app()
else:
    login_page()
