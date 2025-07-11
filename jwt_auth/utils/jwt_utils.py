import os
import frappe
import jwt
from datetime import datetime, timedelta
import uuid
import json
from cryptography.hazmat.primitives import serialization


def load_private_key():
    """Load the RSA private key for JWT signing"""
    try:
        private_key_path = os.path.join(
            frappe.get_app_path('jwt_auth'),
            'config',
            'jwt_private_key.pem'
        )
        
        with open(private_key_path, 'r') as f:
            private_key = f.read()
        
        return private_key
    except Exception as e:
        frappe.log_error(f"Error loading private key: {str(e)}")
        frappe.throw(f"Failed to load private key: {str(e)}")


def load_public_key():
    """Load the RSA public key for JWT verification"""
    try:
        public_key_path = os.path.join(
            frappe.get_app_path('jwt_auth'),
            'config',
            'jwt_public_key.pem'
        )
        
        with open(public_key_path, 'r') as f:
            public_key = f.read()
        
        return public_key
    except Exception as e:
        frappe.log_error(f"Error loading public key: {str(e)}")
        frappe.throw(f"Failed to load public key: {str(e)}")


def generate_jwt_token(user_doc):
    """Generate JWT token for authenticated user"""
    try:
        private_key = load_private_key()
        
        # Get current time
        now = datetime.utcnow()
        
        # Create JWT payload with all required claims
        payload = {
            'iss': frappe.utils.get_url(),  # Issuer
            'sub': user_doc.email,          # Subject (user email)
            'aud': 'https://alphaworkz.api.com',  # Audience (client API)
            'exp': int((now + timedelta(hours=24)).timestamp()),  # Expiration (24 hours)
            'nbf': int(now.timestamp()),    # Not Before
            'iat': int(now.timestamp()),    # Issued At
            'jti': str(uuid.uuid4()),       # JWT ID (unique identifier)
            
            # Custom claims
            'userId': user_doc.username or user_doc.email.split('@')[0],
            'roles': frappe.get_roles(user_doc.email),
            'email': user_doc.email,
            'name': user_doc.full_name or user_doc.first_name
        }
        
        # Generate JWT token using RS256
        token = jwt.encode(payload, private_key, algorithm='RS256')
        
        return {
            'access_token': token,
            'token_type': 'Bearer',
            'expires_in': 86400,  # 24 hours in seconds
            'expires_at': (now + timedelta(hours=24)).isoformat(),
            'user': {
                'userId': payload['userId'],
                'email': payload['email'],
                'name': payload['name'],
                'roles': payload['roles']
            }
        }
        
    except Exception as e:
        frappe.log_error(f"JWT generation error: {str(e)}")
        frappe.throw(f"Failed to generate JWT token: {str(e)}")


def validate_jwt_token(token):
    """Validate JWT token and return user info"""
    try:
        public_key = load_public_key()
        
        # Decode and validate the token
        payload = jwt.decode(
            token,
            public_key,
            algorithms=['RS256'],
            audience='https://alphaworkz.api.com',
            issuer=frappe.utils.get_url()
        )
        
        return payload
    except jwt.ExpiredSignatureError:
        frappe.throw("JWT token has expired")
    except jwt.InvalidTokenError:
        frappe.throw("Invalid JWT token")
    except Exception as e:
        frappe.throw(f"Token validation failed: {str(e)}")


def get_jwks():
    """Generate JSON Web Key Set (JWKS) for public key distribution"""
    try:
        public_key_pem = load_public_key()
        
        # Load the public key using cryptography
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.primitives.asymmetric import rsa
        import base64
        
        public_key = load_pem_public_key(public_key_pem.encode())
        
        # Extract the public key numbers
        public_numbers = public_key.public_numbers()
        
        # Convert to base64url encoding
        def int_to_base64url(value):
            value_bytes = value.to_bytes((value.bit_length() + 7) // 8, 'big')
            return base64.urlsafe_b64encode(value_bytes).decode('ascii').rstrip('=')
        
        # Create JWKS format
        jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": "jwt-auth-key-1",
                    "n": int_to_base64url(public_numbers.n),
                    "e": int_to_base64url(public_numbers.e)
                }
            ]
        }
        
        return jwks
        
    except Exception as e:
        frappe.log_error(f"JWKS generation error: {str(e)}")
        frappe.throw(f"Failed to generate JWKS: {str(e)}")


def validate_user_credentials(email, password):
    """Validate user credentials against Frappe user database"""
    import frappe
    from frappe.auth import check_password
    
    try:
        # Check if user exists and is enabled
        user = frappe.get_doc("User", email)
        if not user.enabled:
            frappe.throw("User is disabled")
        
        # Validate password
        check_password(email, password)
        
        return user  # Return user document instead of True
    except Exception as e:
        frappe.throw(f"Authentication failed: {str(e)}")
