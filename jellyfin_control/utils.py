# jellyfin_control/utils.py

def is_valid_password(password):
    # Implement your password validation logic here
    return len(password) >= 8  # Example: Password should be at least 8 characters long
