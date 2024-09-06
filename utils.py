# utils.py

def hash_password(password: str) -> str:
    # TODO: Implement password hashing
    pass

def verify_password(stored_password: str, provided_password: str) -> bool:
    # TODO: Implement password verification
    pass

def generate_jwt_token(user_id: int, is_admin: bool) -> str:
    # TODO: Implement JWT token generation
    pass

def verify_jwt_token(token: str) -> dict:
    # TODO: Implement JWT token verification
    pass

def log_admin_action(admin_id: int, action_type: str, action_description: str, affected_user_id: int):
    # TODO: Implement admin action logging
    pass

# Add more utility functions as needed