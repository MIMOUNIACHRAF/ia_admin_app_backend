from rest_framework import permissions

class IsAdminOrOwner(permissions.BasePermission):
    """
    Permission qui autorise seulement les admins ou le propriétaire à accéder/modifier un agent.
    """

    def has_object_permission(self, request, view, obj):
        return request.user and (request.user.is_staff or obj.proprietaire == request.user)
