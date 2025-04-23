import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Secure key for Fernet encryption (keep it same for same session)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# Global in-memory storage
stored_data = {}  # Format: {encrypted_text: {encrypted_text: ..., passkey: hashed_passkey}}
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# Hashing function
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt
def decrypt_data(encrypted_text, passkey):
    hashed = hash_passkey(passkey)

    if encrypted_text in stored_data and stored_data[encrypted_text]["passkey"] == hashed:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        return None

# UI
st.title("🛡️ Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("📍 Navigation", menu)

# Home
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Use this app to **securely store and retrieve data** using your own passkey.")

# Store Data
elif choice == "Store Data":
    st.subheader("🔐 Store Data")
    user_data = st.text_area("Enter your data:")
    passkey = st.text_input("Enter a secure passkey:", type="password")

    if st.button("Encrypt & Store"):
        if user_data and passkey:
            encrypted_text = encrypt_data(user_data)
            hashed = hash_passkey(passkey)
            stored_data[encrypted_text] = {"encrypted_text": encrypted_text, "passkey": hashed}
            st.success("✅ Data Encrypted & Stored!")
            st.code(encrypted_text, language='text')
        else:
            st.warning("⚠️ Both fields are required.")

# Retrieve Data
elif choice == "Retrieve Data":
    st.subheader("🔎 Retrieve Data")
    encrypted_text = st.text_area("Paste your encrypted data here:")
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            result = decrypt_data(encrypted_text, passkey)
            if result:
                st.success("✅ Decryption Successful!")
                st.code(result, language='text')
            else:
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey. Attempts left: {attempts_left}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts. Redirecting to Login...")
                    st.experimental_rerun()
        else:
            st.warning("⚠️ Fill all fields.")

# Login (Re-auth)
elif choice == "Login":
    st.subheader("🔑 Reauthorize")
    login = st.text_input("Enter master password:", type="password")

    if st.button("Login"):
        if login == "admin123":  # Demo password
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized successfully! Go to Retrieve Data.")
        else:
            st.error("❌ Incorrect master password.")
