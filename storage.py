import json
import time
import hashlib
import base64
import getpass
from cryptography.fernet import Fernet

MAX_ATTEMPTS = 3
TIMEOUT_SECONDS = 60  # 1 minute

attempts = 0
lockout_time = None


def generate_key(master_password):
    hashed_password = hashlib.sha256(master_password.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(hashed_password[:32]))


def store_password(password, master_password, filename="passwords.json"):
    fernet = generate_key(master_password)
    timestamp = int(time.time())
    encrypted_password = fernet.encrypt(password.encode())

    try:
        with open(filename, "r") as file:
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}

    password_id = f"password_{len(data) + 1}"
    data[password_id] = {"password": encrypted_password.decode(), "timestamp": timestamp}

    with open(filename, "w") as file:
        json.dump(data, file, indent=4)

    print("Password stored securely!")


def retrieve_passwords(master_password, filename="passwords.json"):
    with open(filename, "r") as file:
        data = json.load(file)

    fernet = generate_key(master_password)
    passwords = {}
    for password_id, details in data.items():
        if password_id == "lockout_info":
            continue
        try:
            decrypted_password = fernet.decrypt(details["password"].encode()).decode()
            age = int(time.time()) - details["timestamp"]
            passwords[password_id] = {"password": decrypted_password, "age": age}
        except Exception:
            continue
    return passwords


def retrieve_passwords_secure(filename="passwords.json"):
    global attempts, lockout_time

    try:
        with open(filename, "r") as file:
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}

    lockout_info = data.get("lockout_info", {})
    lockout_time = lockout_info.get("lockout_time", 0)

    if lockout_time and time.time() < lockout_time:
        remaining_time = int(lockout_time - time.time())
        print(f"Too many incorrect attempts. Try again in {remaining_time} seconds.")
        return None

    while attempts < MAX_ATTEMPTS:
        master_password = getpass.getpass("Enter the master password: ")
        try:
            passwords = retrieve_passwords(master_password, filename)
            if passwords:
                print("Passwords retrieved successfully.")
                attempts = 0  # Reset attempts after successful login
                if "lockout_info" in data:
                    del data["lockout_info"]  # Clear lockout info after success
                    with open(filename, "w") as file:
                        json.dump(data, file, indent=4)
                return passwords
            else:
                raise ValueError("No passwords found.")
        except ValueError:
            attempts += 1
            print(f"Incorrect master password. {MAX_ATTEMPTS - attempts} attempts remaining.")

    print("Too many incorrect attempts. Locking out for 1 minute.")
    lockout_time = time.time() + TIMEOUT_SECONDS
    data["lockout_info"] = {"lockout_time": lockout_time}

    with open(filename, "w") as file:
        json.dump(data, file, indent=4)

    return None


def check_password_age(filename="passwords.json", max_age=90*24*60*60):
    try:
        with open(filename, "r") as file:
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        print("No passwords stored.")
        return

    current_time = int(time.time())
    for password_id, details in data.items():
        if isinstance(details, dict) and "timestamp" in details:
            age = current_time - details["timestamp"]
            if age > max_age:
                print(f"Password ID '{password_id}' is too old! Consider updating it.")
            else:
                print(f"Password ID '{password_id}' age is acceptable.")
        else:
            print(f"Skipping malformed entry for password ID '{password_id}'.")

