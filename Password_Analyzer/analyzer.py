import hashlib
import re

def is_breached_password(password, breached_file="breached_passwords.txt"):
    """
    Checks if the given password matches any hash in the breached passwords file.
    """
    # Hash the password (using SHA-1, assuming the file uses SHA-1 hashes)
    hashed_password = hashlib.sha1(password.encode()).hexdigest()

    # Open the breached passwords file and search for the hash
    try:
        with open(breached_file, "r") as file:
            for line in file:
                if hashed_password == line.strip():
                    return True
    except FileNotFoundError:
        print(f"Error: {breached_file} not found.")
        return False

    return False


def check_password_strength(password, breached_file="breached_passwords.txt"):
    """
    Evaluates the strength of a password and checks if it is in the breached list.
    """
    length_ok = len(password) >= 12
    complexity = bool(re.search(r'[A-Z]', password)) and \
                 bool(re.search(r'[a-z]', password)) and \
                 bool(re.search(r'\d', password)) and \
                 bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

    contains_common_patterns = any(pattern in password.lower() for pattern in ["123456", "password", "qwerty"])
    is_breached = is_breached_password(password, breached_file)

    return {
        "length_ok": length_ok,
        "complexity": complexity,
        "contains_common_patterns": contains_common_patterns,
        "is_breached": is_breached
    }
