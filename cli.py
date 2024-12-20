import argparse
from analyzer import check_password_strength
from storage import store_password, retrieve_passwords, check_password_age

def main():
    parser = argparse.ArgumentParser(description="Secure Command-Line Password Strength Analyzer")
    parser.add_argument("command", choices=["analyze", "generate", "store", "retrieve", "check-age"], help="Choose a command.")
    args = parser.parse_args()

    if args.command == "analyze":
        password = input("Enter the password to analyze: ")
        analysis = check_password_strength(password)
        print("Password Analysis:")
        print(f" - Length OK: {analysis['length_ok']}")
        print(f" - Complexity OK: {analysis['complexity']}")
        print(f" - Contains Common Patterns: {analysis['contains_common_patterns']}")
        print(f" - Found in Breached Passwords: {analysis['is_breached']}")

    elif args.command == "store":
        password = input("Enter the password to store: ")
        master_password = input("Enter a master password: ")
        store_password(password, master_password)

    elif args.command == "retrieve":
        master_password = input("Enter the master password: ")
        passwords = retrieve_passwords(master_password)
        if passwords:
            print("Retrieved Passwords:")
            for password_id, password in passwords.items():
                print(f" - {password_id}: {password}")
        else:
            print("No passwords found for the provided master password.")

    elif args.command == "check-age":
        check_password_age()

if __name__ == "__main__":
    main()

