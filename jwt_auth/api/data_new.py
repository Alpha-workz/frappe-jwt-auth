import frappe
from frappe import _
from jwt_auth.auth import get_jwt_user, get_jwt_payload, is_jwt_authenticated


@frappe.whitelist()
def get_oven_job_cards():
    """Get oven job cards - requires JWT authentication"""
    try:
        # Check if JWT authenticated
        if not is_jwt_authenticated():
            frappe.throw(_("JWT authentication required"))
        
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
            "user": get_jwt_user(),
            "message": "Oven job cards retrieved successfully"
        }
        
    except Exception as e:
        frappe.log_error(f"JWT API Error: {str(e)}")
        return {
            "status": "error", 
            "message": str(e)
        }


@frappe.whitelist()
def get_work_orders():
    """Get work orders - requires JWT authentication"""
    try:
        # Check if JWT authenticated
        if not is_jwt_authenticated():
            frappe.throw(_("JWT authentication required"))
        
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
            "user": get_jwt_user(),
            "message": "Work orders retrieved successfully"
        }
        
    except Exception as e:
        frappe.log_error(f"JWT API Error: {str(e)}")
        return {
            "status": "error",
            "message": str(e)
        }


@frappe.whitelist()
def get_item_info(item_code=None):
    """Get item information - requires JWT authentication"""
    try:
        # Check if JWT authenticated
        if not is_jwt_authenticated():
            frappe.throw(_("JWT authentication required"))
        
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
            "user": get_jwt_user(),
            "message": f"Item information retrieved successfully"
        }
        
    except Exception as e:
        frappe.log_error(f"JWT API Error: {str(e)}")
        return {
            "status": "error",
            "message": str(e)
        }


@frappe.whitelist()
def get_user_profile():
    """Get user profile - requires JWT authentication"""
    try:
        # Check if JWT authenticated
        if not is_jwt_authenticated():
            frappe.throw(_("JWT authentication required"))
        
        jwt_user = get_jwt_user()
        jwt_payload = get_jwt_payload()
        
        # Get user profile
        user_doc = frappe.get_doc("User", jwt_user)
        
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
                "jwt_payload": jwt_payload
            },
            "message": "User profile retrieved successfully"
        }
        
    except Exception as e:
        frappe.log_error(f"JWT API Error: {str(e)}")
        return {
            "status": "error",
            "message": str(e)
        }
