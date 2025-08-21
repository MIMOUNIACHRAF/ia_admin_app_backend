from rest_framework import permissions

class IsAdminOrOwner(permissions.BasePermission):
    """
    Permission qui autorise seulement :
    - les admins (is_staff ou superuser)
    - OU le propriétaire de l'objet
    """

    def has_object_permission(self, request, view, obj):
        return (
            request.user
            and request.user.is_authenticated
            and (request.user.is_staff or obj.proprietaire == request.user)
        )
