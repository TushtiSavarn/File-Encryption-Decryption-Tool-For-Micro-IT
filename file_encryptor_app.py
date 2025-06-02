import streamlit as st
import os
from cryptography.fernet import Fernet
import hashlib
import base64
from tempfile import NamedTemporaryFile

# --- Utility Functions ---

def generate_fernet_key(password: str) -> bytes:
    key = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(key)

def calculate_sha256(file_data: bytes) -> str:
    return hashlib.sha256(file_data).hexdigest()

def encrypt_file(file_data: bytes, password: str) -> bytes:
    key = generate_fernet_key(password)
    cipher = Fernet(key)
    return cipher.encrypt(file_data)

def decrypt_file(file_data: bytes, password: str) -> bytes:
    key = generate_fernet_key(password)
    cipher = Fernet(key)
    return cipher.decrypt(file_data)

# --- Streamlit App ---

st.set_page_config(page_title="🔐 File Encryption Tool", layout="centered")
st.title("🔐 File Encryption / Decryption Tool")
st.markdown("Encrypt or decrypt your files securely using a password. Built with `Streamlit` + `cryptography`.")

action = st.radio("Choose Action", ["Encrypt File", "Decrypt File", "Bulk Encrypt"])

password = st.text_input("Enter Password", type="password")

if password:
    if action == "Encrypt File":
        uploaded_file = st.file_uploader("Choose a file to encrypt", type=None)
        if uploaded_file:
            file_bytes = uploaded_file.read()
            hash_before = calculate_sha256(file_bytes)

            if st.button("Encrypt Now"):
                try:
                    encrypted_data = encrypt_file(file_bytes, password)
                    st.success("✅ File Encrypted Successfully")
                    st.write(f"SHA256 (Original): `{hash_before}`")

                    st.download_button("Download Encrypted File", encrypted_data, file_name=uploaded_file.name + ".enc")
                except Exception as e:
                    st.error(f"Encryption failed: {e}")

    elif action == "Decrypt File":
        uploaded_file = st.file_uploader("Choose a file to decrypt", type=["enc"])
        if uploaded_file:
            file_bytes = uploaded_file.read()
            if st.button("Decrypt Now"):
                try:
                    decrypted_data = decrypt_file(file_bytes, password)
                    st.success("✅ File Decrypted Successfully")
                    hash_after = calculate_sha256(decrypted_data)
                    st.write(f"SHA256 (Decrypted): `{hash_after}`")

                    st.download_button("Download Decrypted File", decrypted_data, file_name="decrypted_" + uploaded_file.name.replace(".enc", ""))
                except Exception as e:
                    st.error("Decryption failed! Wrong password or corrupt file.")

    elif action == "Bulk Encrypt":
        uploaded_files = st.file_uploader("Select multiple files", accept_multiple_files=True)
        if uploaded_files and st.button("Encrypt All Files"):
            st.success("Files encrypted! Download below:")
            for file in uploaded_files:
                try:
                    data = file.read()
                    encrypted_data = encrypt_file(data, password)
                    st.download_button(f"Download {file.name}.enc", encrypted_data, file_name=file.name + ".enc", key=file.name)
                except Exception as e:
                    st.error(f"Failed to encrypt {file.name}: {e}")
else:
    st.warning("Please enter a password to proceed.")

st.markdown("---")
st.caption("Made with ❤️ using Python + Streamlit")
