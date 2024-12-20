import hashlib
import re
from utils import calculate_entropy


def is_breached_password(password, breached_file="breached_passwords.txt"):
    """Checks if the given password matches any hash in the breached passwords file."""
    hashed_password = hashlib.sha1(password.encode()).hexdigest()
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
    """Evaluates the strength of a password and checks if it is in the breached list."""
    length_ok = len(password) >= 12
    complexity = bool(re.search(r'[A-Z]', password)) and \
                 bool(re.search(r'[a-z]', password)) and \
                 bool(re.search(r'\d', password)) and \
                 bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    contains_common_patterns = any(pattern in password.lower() for pattern in ["123456", "password", "qwerty"])
    is_breached = is_breached_password(password, breached_file)
    entropy = calculate_entropy(password)

    return {
        "length_ok": length_ok,
        "complexity": complexity,
        "contains_common_patterns": contains_common_patterns,
        "is_breached": is_breached,
        "entropy": entropy
    }


def provide_feedback(analysis):
    """Provides actionable feedback based on password analysis."""
    feedback = []
    if not analysis["length_ok"]:
        feedback.append("Password should be at least 12 characters long.")
    if not analysis["complexity"]:
        feedback.append("Password should include upper and lowercase letters, numbers, and symbols.")
    if analysis["contains_common_patterns"]:
        feedback.append("Avoid using common patterns like '123456', 'password', or 'qwerty'.")
    if analysis["is_breached"]:
        feedback.append("This password appears in a breached database. Avoid reusing it.")
    if analysis["entropy"] < 50:
        feedback.append("Password entropy is too low. Consider using a longer, more complex password.")
    return feedback

