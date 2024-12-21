import argparse
import pyperclip
from analyzer import check_password_strength, provide_feedback
from storage import store_password, retrieve_passwords_secure, check_password_age

def generate_password(length=16):
    """Generate a strong random password."""
    import random
    import string
    charset = string.ascii_letters + string.digits + "!@#$%^&*(),.?\":{}|<>"
    password = ''.join(random.choice(charset) for _ in range(length))
    pyperclip.copy(password)
    print("Generated password copied to clipboard!")
    return password


def display_help():
    """Display detailed help for all available commands."""
    help_text = """
    Secure Command-Line Password Strength Analyzer

    Available Commands:
    -------------------
    new          - Generate a new password or enter an existing one. Analyze its strength,
                   get recommendations, and optionally store it securely.
    analyze      - Analyze the strength of a password, including its length, complexity,
                   entropy, and whether it has been breached. Provides actionable feedback.
    retrieve     - Retrieve all stored passwords. Includes the age of each password.
    check-age    - Check if any stored passwords are older than the specified age (default 90 days).

    Usage Examples:
    ----------------
    python cli.py new          # Generate or analyze a password
    python cli.py analyze      # Analyze a password
    python cli.py retrieve     # Retrieve stored passwords
    python cli.py check-age    # Check for outdated passwords
    """
    print(help_text)


def main():
    parser = argparse.ArgumentParser(description="Secure Command-Line Password Strength Analyzer")
    parser.add_argument(
        "command",
        nargs="?",
        choices=["new", "analyze", "retrieve", "check-age"],
        help="Choose a command.",
    )
    parser.add_argument(
        "-help",
        action="store_true",
        help="Display detailed help for all available commands."
    )
    args = parser.parse_args()

    if args.help:
        display_help()
        return

    if args.command == "new":
        generate = input("Do you want to generate a password? (yes/no): ").strip().lower()
        if generate == "yes":
            password = generate_password()
            print(f"Generated Password: {password}")
            store = input("Do you want to store the generated password? (yes/no): ").strip().lower()
            if store == "yes":
                master_password = input("Enter a master password: ")
                store_password(password, master_password)
        else:
            password = input("Enter a password to analyze: ")
            analysis = check_password_strength(password)
            entropy = analysis["entropy"]
            print(f"Password Entropy: {entropy:.2f}")
            feedback = provide_feedback(analysis)
            if feedback:
                print("Recommendations:")
                for suggestion in feedback:
                    print(f" - {suggestion}")
            if entropy < 50 or not analysis["length_ok"] or not analysis["complexity"]:
                confirm = input("This password is weak. Are you sure you want to use it? (yes/no): ").strip().lower()
                if confirm != "yes":
                    print("Password rejected. Please choose another.")
                    return
            store = input("Do you want to store this password? (yes/no): ").strip().lower()
            if store == "yes":
                master_password = input("Enter a master password: ")
                store_password(password, master_password)

    elif args.command == "analyze":
        password = input("Enter the password to analyze: ")
        analysis = check_password_strength(password)
        print("Password Analysis:")
        print(f" - Length OK: {analysis['length_ok']}")
        print(f" - Complexity OK: {analysis['complexity']}")
        print(f" - Contains Common Patterns: {analysis['contains_common_patterns']}")
        print(f" - Found in Breached Passwords: {analysis['is_breached']}")
        print(f" - Entropy Score: {analysis['entropy']:.2f}")
        feedback = provide_feedback(analysis)
        if feedback:
            print("Recommendations:")
            for suggestion in feedback:
                print(f" - {suggestion}")

    elif args.command == "retrieve":
        passwords = retrieve_passwords_secure()
        if passwords is None:
            print("Access denied due to repeated incorrect attempts. Please try again later.")
            return
        if passwords:
            print("Retrieved Passwords:")
            for password_id, details in passwords.items():
                age_days = details["age"] // (24 * 60 * 60)
                print(f" - {password_id}: {details['password']} (Age: {age_days} days)")


    elif args.command == "check-age":
        check_password_age()
    else:
        print("No command provided. Use -help to see available commands.")


if __name__ == "__main__":
    main()
