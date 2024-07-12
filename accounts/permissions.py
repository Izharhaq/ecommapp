from rest_framework.permissions import BasePermission, SAFE_METHODS

class IsReadAndEdit(BasePermission):
    def has_permission(self, request, view):
        user = request.user
        # Superuser has full access
        if user.is_superuser:
            return user.role in ['user', 'admin']

        if user.is_authenticated:
            # Read-only permissions
            if request.method in SAFE_METHODS:
                return True  # All authenticated users can read

            # Edit permissions (POST, PUT, PATCH)
            if request.method in ['POST', 'PUT', 'PATCH']:
                return user.role in ['user', 'admin']  # Allow editing for 'editor' and 'admin' roles

            # Delete permissions
            if request.method == 'DELETE':
                return user.role == 'admin'  # Allow deleting for 'admin' role

        return False
    
class IsAdminUser(BasePermission):
    """
    Allows access only to admin users.
    """
    def has_permission(self, request, view):
        # Check if the user is authenticated and has the 'admin' role
        return request.user.is_authenticated and request.user.role == 'admin'