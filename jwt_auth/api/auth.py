import frappe
import jwt
from datetime import datetime, timedelta
from jwt_auth.utils.jwt_utils import generate_jwt_token, validate_user_credentials

@frappe.whitelist(allow_guest=True)
def health():
    """Health check endpoint"""
    return {
        "status": "ok",
        "message": "JWT Auth service is running",
        "timestamp": frappe.utils.now()
    }

@frappe.whitelist(allow_guest=True)
def login():
    """
    JWT Authentication endpoint
    Expects: {"username": "user", "password": "pass"}
    Returns: JWT token with RS256 signature
    """
    try:
        # Get request data
        data = frappe.local.form_dict
        
        # Validate required fields
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            frappe.local.response.http_status_code = 400
            return {
                "error": "Missing username or password",
                "message": "Both username and password are required"
            }
        
        # Get client IP for logging
        client_ip = frappe.local.request.environ.get('REMOTE_ADDR', 'unknown')
        
        # Validate user credentials
        user_doc = validate_user_credentials(username, password)
        
        if not user_doc:
            frappe.local.response.http_status_code = 401
            frappe.logger().warning(f"Failed login attempt for {username} from {client_ip}")
            return {
                "error": "Invalid credentials",
                "message": "Username or password is incorrect"
            }
        
        # Generate JWT token
        token_data = generate_jwt_token(user_doc)
        
        # Log successful authentication
        frappe.logger().info(f"Successful JWT login for {username} from {client_ip}")
        
        # Return token
        frappe.local.response.http_status_code = 200
        return token_data
        
    except Exception as e:
        frappe.log_error(f"JWT Login Error: {str(e)}", "JWT Auth")
        frappe.local.response.http_status_code = 500
        return {
            "error": "Internal server error",
            "message": "Authentication service temporarily unavailable"
        }

@frappe.whitelist()
def verify_token():
    """
    Verify JWT token endpoint (for testing)
    Expects Authorization: Bearer <token>
    """
    try:
        # Get Authorization header
        auth_header = frappe.get_request_header("Authorization")
        
        if not auth_header or not auth_header.startswith("Bearer "):
            frappe.local.response.http_status_code = 401
            return {
                "error": "Missing or invalid authorization header",
                "message": "Authorization header must be 'Bearer <token>'"
            }
        
        # Extract token
        token = auth_header.split(" ")[1]
        
        # Validate token (this will be implemented in jwt_utils)
        from jwt_auth.utils.jwt_utils import validate_jwt_token
        payload = validate_jwt_token(token)
        
        return {
            "valid": True,
            "payload": payload,
            "message": "Token is valid"
        }
        
    except Exception as e:
        frappe.local.response.http_status_code = 401
        return {
            "valid": False,
            "error": str(e),
            "message": "Token validation failed"
        }
