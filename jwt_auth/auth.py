import frappe
from frappe import _
import jwt
import os
from jwt_auth.utils.jwt_utils import load_private_key, load_public_key


def validate_jwt_auth():
    """Custom authentication hook for JWT Bearer tokens"""
    
    # Get authorization header
    auth_header = frappe.get_request_header('Authorization')
    
    # If no Authorization header, let Frappe handle normal authentication
    if not auth_header:
        return None
    
    # If not Bearer token, let Frappe handle normal authentication
    if not auth_header.startswith('Bearer '):
        return None
    
    try:
        # Extract token
        token = auth_header.split(' ')[1]
        
        # Load public key
        public_key = load_public_key()
        
        # Decode and validate the token
        payload = jwt.decode(
            token,
            public_key,
            algorithms=['RS256'],
            audience='https://alphaworkz.api.com',
            issuer=frappe.utils.get_url()
        )
        
        # Get user email from JWT payload
        user_email = payload.get('sub')
        
        if not user_email:
            raise frappe.AuthenticationError(_("Invalid JWT payload: missing subject"))
        
        # Verify user exists and is enabled
        user = frappe.get_doc("User", user_email)
        if not user or user.enabled != 1:
            raise frappe.AuthenticationError(_("User not found or disabled"))
        
        # Set user in frappe context
        frappe.set_user(user_email)
        frappe.local.jwt_user = user_email
        frappe.local.jwt_payload = payload
        
        return user_email
        
    except jwt.ExpiredSignatureError:
        frappe.throw(_("JWT token has expired"), frappe.AuthenticationError)
    except jwt.InvalidTokenError:
        frappe.throw(_("Invalid JWT token"), frappe.AuthenticationError)
    except Exception as e:
        frappe.log_error(f"JWT Auth Error: {str(e)}")
        frappe.throw(_("JWT authentication failed"), frappe.AuthenticationError)


def on_session_creation(login_manager):
    """Called when a session is created"""
    # This is for regular login sessions, not JWT
    pass


def get_jwt_user():
    """Get current JWT authenticated user"""
    return getattr(frappe.local, 'jwt_user', None)


def get_jwt_payload():
    """Get current JWT payload"""
    return getattr(frappe.local, 'jwt_payload', None)


def is_jwt_authenticated():
    """Check if current request is JWT authenticated"""
    return hasattr(frappe.local, 'jwt_user')
