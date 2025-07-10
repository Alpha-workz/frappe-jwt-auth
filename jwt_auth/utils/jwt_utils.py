import jwt
import frappe
import uuid
from datetime import datetime, timedelta
from frappe.utils import get_datetime
import os

def get_private_key():
    """Load the RSA private key for JWT signing"""
    try:
        key_path = os.path.join(frappe.get_app_path("jwt_auth"), "config", "jwt_private_key.pem")
        with open(key_path, 'r') as key_file:
            return key_file.read()
    except Exception as e:
        frappe.log_error(f"Failed to load private key: {str(e)}", "JWT Auth")
        frappe.throw("JWT private key not found")

def get_public_key():
    """Load the RSA public key for JWT verification"""
    try:
        key_path = os.path.join(frappe.get_app_path("jwt_auth"), "config", "jwt_public_key.pem")
        with open(key_path, 'r') as key_file:
            return key_file.read()
    except Exception as e:
        frappe.log_error(f"Failed to load public key: {str(e)}", "JWT Auth")
        frappe.throw("JWT public key not found")

def filter_manufacturing_roles(roles):
    """Filter roles to include only manufacturing-related ones"""
    manufacturing_roles = [
        "Oven Operator", "Mill Operator", "Batch Operator", 
        "Moulding Supervisor", "Production Executive", "Quality Executive",
        "Line Inspector", "Lot Inspector", "Incoming Inspector", 
        "Despatcher", "Packer", "Compound Inspector", "Blanker",
        "U1 Supervisor", "U2 Supervisor", "U3 Supervisor"
    ]
    
    # Include System Manager and Administrator for admin access
    admin_roles = ["System Manager", "Administrator"]
    
    # Filter roles
    filtered_roles = []
    for role in roles:
        if role in manufacturing_roles or role in admin_roles:
            filtered_roles.append(role)
    
    return filtered_roles if filtered_roles else ["Guest"]

def generate_jwt_token(user_email):
    """
    Generate a JWT token for the given user using RS256 algorithm
    
    Args:
        user_email (str): Email of the user
        
    Returns:
        dict: Contains token and user information
    """
    try:
        frappe.logger().info(f"Starting JWT generation for user: {user_email}")
        
        # Get user document
        user_doc = frappe.get_doc("User", user_email)
        
        if not user_doc.enabled:
            frappe.throw("User account is disabled")
            
        # Get user roles and filter manufacturing ones
        all_roles = frappe.get_roles(user_email)
        user_roles = filter_manufacturing_roles(all_roles)
        
        frappe.logger().info(f"User roles: {user_roles}")
        
        # Current time
        now = datetime.utcnow()
        expiry_hours = 24  # 24 hours expiry
        
        # Create JWT payload with exact structure required by client
        payload = {
            # Standard JWT claims
            "iss": "https://sppmaster.frappe.cloud",  # Will be updated for production
            "sub": user_email,  # Subject (user identifier)
            "aud": "https://alphaworkz.api.com",  # Audience (client API)
            "exp": int((now + timedelta(hours=expiry_hours)).timestamp()),  # Expiry timestamp
            "nbf": int(now.timestamp()),  # Not before timestamp
            "iat": int(now.timestamp()),  # Issued at timestamp
            "jti": str(uuid.uuid4()),  # Unique JWT ID
            
            # Custom claims as required by client
            "userId": user_doc.username or user_email.split('@')[0],  # Username part
            "roles": user_roles,  # Filtered roles array
            "email": user_email,  # User email
            "name": user_doc.full_name or user_doc.first_name or "Unknown User"  # Full name
        }
        
        frappe.logger().info(f"JWT payload created: {payload}")
        
        # Load private key and generate token
        private_key = get_private_key()
        token = jwt.encode(payload, private_key, algorithm="RS256")
        
        frappe.logger().info("JWT token generated successfully")
        
        # Return token info
        return {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": expiry_hours * 3600,  # Convert to seconds
            "expires_at": (now + timedelta(hours=expiry_hours)).isoformat(),
            "user": {
                "userId": payload["userId"],
                "email": user_email,
                "name": payload["name"],
                "roles": user_roles
            }
        }
        
    except Exception as e:
        frappe.log_error(f"JWT Token Generation Error: {str(e)}", "JWT Auth")
        frappe.logger().error(f"JWT generation failed: {str(e)}")
        frappe.throw(f"Failed to generate JWT token: {str(e)}")

def validate_user_credentials(username, password):
    """
    Validate user credentials against Frappe user system
    
    Args:
        username (str): Username or email
        password (str): Password
        
    Returns:
        str: User email if valid, None if invalid
    """
    try:
        frappe.logger().info(f"Validating credentials for user: {username}")
        
        # Try to authenticate user
        user = frappe.get_doc("User", username)
        
        if not user or not user.enabled:
            frappe.logger().info(f"User not found or disabled: {username}")
            return None
            
        # Check password
        from frappe.utils.password import check_password
        if check_password(username, password):
            frappe.logger().info(f"Authentication successful for user: {username}")
            return username
        else:
            frappe.logger().info(f"Invalid password for user: {username}")
            return None
            
    except frappe.DoesNotExistError:
        frappe.logger().info(f"User does not exist: {username}")
        return None
    except Exception as e:
        frappe.logger().error(f"Authentication error: {str(e)}")
        return None

def validate_jwt_token(token):
    """
    Validate a JWT token using RS256 algorithm
    
    Args:
        token (str): JWT token to validate
        
    Returns:
        dict: Token payload if valid
        
    Raises:
        jwt.InvalidTokenError: If token is invalid
    """
    try:
        public_key = get_public_key()
        payload = jwt.decode(token, public_key, algorithms=["RS256"])
        
        # Additional validation if needed
        user_email = payload.get("sub")
        if user_email:
            # Check if user still exists and is enabled
            user_doc = frappe.get_doc("User", user_email)
            if not user_doc.enabled:
                raise jwt.InvalidTokenError("User account is disabled")
        
        return payload
        
    except jwt.ExpiredSignatureError:
        frappe.throw("Token has expired")
    except jwt.InvalidTokenError as e:
        frappe.throw(f"Invalid token: {str(e)}")
    except Exception as e:
        frappe.log_error(f"JWT Validation Error: {str(e)}", "JWT Auth")
        frappe.throw(f"Token validation failed: {str(e)}")

def extract_bearer_token(authorization_header):
    """
    Extract JWT token from Authorization header
    
    Args:
        authorization_header (str): Authorization header value
        
    Returns:
        str: JWT token or None
    """
    if not authorization_header:
        return None
        
    parts = authorization_header.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return None
        
    return parts[1]

def get_public_key_content():
    """
    Get the public key content as string
    Safe to expose publicly
    """
    public_key_path = os.path.join(
        frappe.get_app_path('jwt_auth'), 
        'config', 
        'jwt_public_key.pem'
    )
    
    if not os.path.exists(public_key_path):
        frappe.throw("Public key file not found")
    
    with open(public_key_path, 'r') as f:
        return f.read()

def get_jwks_format():
    """
    Get public key in JWKS (JSON Web Key Set) format
    Standard format for key distribution
    """
    import base64
    from cryptography.hazmat.primitives import serialization
    
    try:
        # Load the public key
        public_key_pem = get_public_key_content()
        
        # Parse the public key
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        public_key = load_pem_public_key(public_key_pem.encode())
        
        # Get the public numbers
        public_numbers = public_key.public_numbers()
        
        # Convert to base64url format (JWKS standard)
        def int_to_base64url(val):
            val_bytes = val.to_bytes((val.bit_length() + 7) // 8, 'big')
            return base64.urlsafe_b64encode(val_bytes).decode('ascii').rstrip('=')
        
        return {
            "kty": "RSA",  # Key type
            "use": "sig",  # Key use (signature)
            "alg": "RS256",  # Algorithm
            "kid": "jwt-auth-key-1",  # Key ID
            "n": int_to_base64url(public_numbers.n),  # Modulus
            "e": int_to_base64url(public_numbers.e),  # Exponent
        }
        
    except Exception as e:
        frappe.log_error(f"JWKS format error: {str(e)}", "JWT Auth")
        frappe.throw("Failed to generate JWKS format")

def get_key_fingerprint():
    """
    Get a fingerprint of the public key for verification
    """
    import hashlib
    
    public_key_content = get_public_key_content()
    fingerprint = hashlib.sha256(public_key_content.encode()).hexdigest()[:16]
    return fingerprint
