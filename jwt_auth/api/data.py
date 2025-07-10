import frappe
from frappe import _
import jwt
from datetime import datetime
import os


def validate_jwt_token(token):
    """Validate JWT token and return user info"""
    try:
        # Get the public key
        public_key_path = os.path.join(
            frappe.get_app_path('jwt_auth'),
            'config',
            'jwt_public_key.pem'
        )
        
        with open(public_key_path, 'r') as f:
            public_key = f.read()
        
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
        frappe.throw(_("JWT token has expired"))
    except jwt.InvalidTokenError:
        frappe.throw(_("Invalid JWT token"))
    except Exception as e:
        frappe.throw(_("Token validation failed: {0}").format(str(e)))


@frappe.whitelist(allow_guest=True)
def get_oven_job_cards():
    """Get oven job cards with JWT authentication"""
    try:
        # Get authorization header
        auth_header = frappe.get_request_header('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            frappe.throw(_("Authorization header missing or invalid"))
        
        # Extract token
        token = auth_header.split(' ')[1]
        
        # Validate JWT token
        payload = validate_jwt_token(token)
        
        # Set user context based on JWT payload
        frappe.set_user(payload.get('sub'))
        
        # Get oven job cards data
        job_cards = frappe.get_all(
            "Job Card",
            filters={
                "workstation": ["like", "%oven%"]
            },
            fields=[
                "name",
                "operation",
                "workstation",
                "status",
                "expected_start_date",
                "expected_end_date",
                "actual_start_date",
                "actual_end_date",
                "work_order",
                "item_code",
                "item_name",
                "for_quantity"
            ],
            order_by="creation desc",
            limit=50
        )
        
        return {
            "status": "success",
            "data": job_cards,
            "count": len(job_cards),
            "user": payload.get('email'),
            "message": "Oven job cards retrieved successfully"
        }
        
    except Exception as e:
        frappe.log_error(f"JWT API Error: {str(e)}")
        return {
            "status": "error",
            "message": str(e)
        }


@frappe.whitelist(allow_guest=True)
def get_work_orders():
    """Get work orders with JWT authentication"""
    try:
        # Get authorization header
        auth_header = frappe.get_request_header('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            frappe.throw(_("Authorization header missing or invalid"))
        
        # Extract token
        token = auth_header.split(' ')[1]
        
        # Validate JWT token
        payload = validate_jwt_token(token)
        
        # Set user context based on JWT payload
        frappe.set_user(payload.get('sub'))
        
        # Get work orders data
        work_orders = frappe.get_all(
            "Work Order",
            fields=[
                "name",
                "item_code",
                "item_name",
                "qty",
                "produced_qty",
                "status",
                "planned_start_date",
                "planned_end_date",
                "actual_start_date",
                "actual_end_date",
                "production_item",
                "bom_no",
                "company"
            ],
            order_by="creation desc",
            limit=50
        )
        
        return {
            "status": "success",
            "data": work_orders,
            "count": len(work_orders),
            "user": payload.get('email'),
            "message": "Work orders retrieved successfully"
        }
        
    except Exception as e:
        frappe.log_error(f"JWT API Error: {str(e)}")
        return {
            "status": "error",
            "message": str(e)
        }


@frappe.whitelist(allow_guest=True)
def get_item_info(item_code=None):
    """Get item information with JWT authentication"""
    try:
        # Get authorization header
        auth_header = frappe.get_request_header('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            frappe.throw(_("Authorization header missing or invalid"))
        
        # Extract token
        token = auth_header.split(' ')[1]
        
        # Validate JWT token
        payload = validate_jwt_token(token)
        
        # Set user context based on JWT payload
        frappe.set_user(payload.get('sub'))
        
        # Get item data
        filters = {}
        if item_code:
            filters['item_code'] = item_code
        
        items = frappe.get_all(
            "Item",
            filters=filters,
            fields=[
                "name",
                "item_code",
                "item_name",
                "item_group",
                "description",
                "stock_uom",
                "is_stock_item",
                "valuation_rate",
                "standard_rate",
                "creation",
                "modified"
            ],
            order_by="creation desc",
            limit=20 if not item_code else 1
        )
        
        return {
            "status": "success",
            "data": items,
            "count": len(items),
            "user": payload.get('email'),
            "message": f"Item information retrieved successfully"
        }
        
    except Exception as e:
        frappe.log_error(f"JWT API Error: {str(e)}")
        return {
            "status": "error",
            "message": str(e)
        }


@frappe.whitelist(allow_guest=True)
def get_user_profile():
    """Get user profile with JWT authentication"""
    try:
        # Get authorization header
        auth_header = frappe.get_request_header('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            frappe.throw(_("Authorization header missing or invalid"))
        
        # Extract token
        token = auth_header.split(' ')[1]
        
        # Validate JWT token
        payload = validate_jwt_token(token)
        
        # Set user context based on JWT payload
        frappe.set_user(payload.get('sub'))
        
        # Get user profile
        user_doc = frappe.get_doc("User", payload.get('sub'))
        
        return {
            "status": "success",
            "data": {
                "email": user_doc.email,
                "full_name": user_doc.full_name,
                "username": user_doc.username,
                "roles": frappe.get_roles(user_doc.email),
                "user_type": user_doc.user_type,
                "enabled": user_doc.enabled,
                "last_login": user_doc.last_login,
                "creation": user_doc.creation,
                "jwt_payload": payload
            },
            "message": "User profile retrieved successfully"
        }
        
    except Exception as e:
        frappe.log_error(f"JWT API Error: {str(e)}")
        return {
            "status": "error",
            "message": str(e)
        }
