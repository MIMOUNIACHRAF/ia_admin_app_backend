# auth_admin/authentication.py
from rest_framework_simplejwt.authentication import JWTAuthentication

class MiddlewareAwareJWTAuthentication(JWTAuthentication):
    """
    JWTAuthentication qui utilise le nouveau access token injecté par le middleware
    si le token initial est expiré.
    """
    def authenticate(self, request):
        # Si middleware a généré un nouveau access token
        new_access = request.META.get("NEW_ACCESS_TOKEN", None)
        if new_access:
            # Injecte dans request.META pour DRF
            request.META["HTTP_AUTHORIZATION"] = f"Bearer {new_access}"
        return super().authenticate(request)
