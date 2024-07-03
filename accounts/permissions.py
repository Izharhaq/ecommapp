# from rest_framework.permissions import BasePermission, SAFE_METHODS

# class IsReadOnly(BasePermission):
#     def has_permission(self, request, view):
#         return request.user.is_authenticated and request.user.role_id == 1

# class IsReadAndEdit(BasePermission):
#     def has_permission(self, request, view):
#         if request.user.is_authenticated:
#             if request.user.role_id == 2:
#                 return request.method in SAFE_METHODS or request.method == 'PUT'
#             elif request.user.role_id == 3:
#                 return True
#         return False

# class IsAdmin(BasePermission):
#     def has_permission(self, request, view):
#         return request.user.is_authenticated and request.user.role_id == 3

from rest_framework.permissions import BasePermission, SAFE_METHODS

class IsReadAndEdit(BasePermission):
    def has_permission(self, request, view):
        if request.user.is_authenticated:
            # Check if the user is trying to perform a safe (read-only) operation
            if request.method in SAFE_METHODS:
                return request.user.role_id in [1, 2, 3]  # Users with role_id 1, 2, and 3 can read
            # Check if the user is trying to perform an edit (non-destructive) operation
            elif request.method in ['PUT', 'PATCH']:
                return request.user.role_id in [2, 3]  # Users with role_id 2 and 3 can edit
            # Check if the user is trying to perform a delete operation
            elif request.method == 'DELETE':
                return request.user.role_id == 3  # Only users with role_id 3 (admins) can delete
        return False

