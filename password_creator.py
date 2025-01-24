import re
import getpass

def validate_password(password):
    """
    Validates the password based on predefined criteria.
    Criteria:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least one special character
    """
    if len(password) < 8:
        print("Password must be at least 8 characters long.")
        return False
    if not re.search(r"[A-Z]", password):
        print("Password must contain at least one uppercase letter.")
        return False
    if not re.search(r"[a-z]", password):
        print("Password must contain at least one lowercase letter.")
        return False
    if not re.search(r"[0-9]", password):
        print("Password must contain at least one number.")
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        print("Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>).")
        return False
    return True

def create_password():
    """
    Prompts the user to create a password, validates it, and confirms it.
    """
    while True:
        print("\nCreate a strong password following these rules:")
        print("- At least 8 characters long")
        print("- Contains uppercase and lowercase letters")
        print("- Includes at least one number")
        print("- Includes at least one special character (!@#$%^&*(),.?\":{}|<>)")
        
        # Use getpass to hide the password input in the terminal
        password = getpass.getpass("Enter your password: ")
        confirm_password = getpass.getpass("Confirm your password: ")

        if password != confirm_password:
            print("Passwords do not match. Please try again.")
            continue

        if validate_password(password):
            print("\nPassword created successfully!")
            break
        else:
            print("Please try again.\n")

if __name__ == "__main__":
    create_password()
