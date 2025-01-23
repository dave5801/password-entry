import bcrypt

# Hashing a password
def hash_password(plain_password):
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(plain_password.encode('utf-8'), salt)
    return hashed_password

# Verifying a password
def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)

if __name__ == "__main__":
    # Example usage
    password = "my_secure_password"
    hashed = hash_password(password)
    print(f"Hashed Password: {hashed}")

    # Verify
    is_valid = verify_password("my_secure_password", hashed)
    print(f"Password is valid: {is_valid}")