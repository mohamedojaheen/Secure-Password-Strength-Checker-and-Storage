import json
from cryptography.fernet import Fernet
import time
import hashlib
import base64

def generate_key(master_password):
    """Derive a consistent encryption key from the master password."""
    hashed_password = hashlib.sha256(master_password.encode()).digest()  # Use SHA-256 for hashing
    return Fernet(base64.urlsafe_b64encode(hashed_password[:32]))  # Use the first 32 bytes

def store_password(password, master_password, filename="passwords.json"):
    """Encrypt and store a password with a timestamp."""
    fernet = generate_key(master_password)
    timestamp = int(time.time())
    encrypted_password = fernet.encrypt(password.encode())

    # Read existing passwords from file
    try:
        with open(filename, "r") as file:
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}

    # Generate a unique identifier for this password
    password_id = f"password_{len(data) + 1}"
    data[password_id] = {"password": encrypted_password.decode(), "timestamp": timestamp}

    # Write back to the file
    with open(filename, "w") as file:
        json.dump(data, file, indent=4)

    print("Password stored securely!")

def retrieve_passwords(master_password, filename="passwords.json"):
    """Decrypt and retrieve all stored passwords."""
    with open(filename, "r") as file:
        data = json.load(file)

    fernet = generate_key(master_password)
    passwords = {}

    for password_id, details in data.items():
        try:
            decrypted_password = fernet.decrypt(details["password"].encode()).decode()
            passwords[password_id] = decrypted_password
        except Exception:
            # Skip passwords that can't be decrypted with this master password
            continue

    return passwords


def check_password_age(filename="passwords.json", max_age=90*24*60*60):
    """Check if any stored password is too old."""
    try:
        with open(filename, "r") as file:
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        print("No passwords stored.")
        return

    current_time = int(time.time())
    found_old_password = False

    for password_id, details in data.items():
        if isinstance(details, dict) and "timestamp" in details:
            age = current_time - details["timestamp"]
            if age > max_age:
                print(f"Password ID '{password_id}' is too old! Consider updating it.")
                found_old_password = True
            else:
                print(f"Password ID '{password_id}' age is acceptable.")
        else:
            print(f"Skipping malformed entry for password ID '{password_id}'.")

    if not found_old_password:
        print("All passwords are within the acceptable age range.")

