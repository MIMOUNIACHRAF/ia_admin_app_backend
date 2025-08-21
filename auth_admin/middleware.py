# auth_admin/middleware.py
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework.authentication import get_authorization_header
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import TokenError
from django.http import JsonResponse
import logging
import jwt

logger = logging.getLogger(__name__)

class RefreshAccessMiddleware(MiddlewareMixin):
    """
    Middleware strict avec rotation d'Access Token :
    - Access token requis
    - Vérifie correspondance avec refresh token
    - Vérifie la syntaxe de l'access token
    - Si expiré mais valide → génère un nouveau access token
    """

    def process_request(self, request):
        if request.method == "OPTIONS":
            return

        path = request.path
        public_paths = ["/api/auth/login/", "/api/auth/refresh/", "/api/auth/logout/"]
        if any(path.startswith(p) for p in public_paths):
            return

        refresh_cookie = request.COOKIES.get("refresh_token")
        if not refresh_cookie:
            logger.debug("[RefreshAccessMiddleware] Refresh token absent.")
            return self._unauthorized_response("Refresh token absent ou expiré.")

        # Vérifie refresh token d'abord
        try:
            refresh = RefreshToken(refresh_cookie)
        except TokenError:
            logger.debug("[RefreshAccessMiddleware] Refresh token invalide ou expiré.")
            return self._unauthorized_response("Refresh token invalide ou expiré.")

        # Récupérer l'utilisateur
        user_id_claim = settings.SIMPLE_JWT.get("USER_ID_CLAIM", "user_id")
        refresh_uid = refresh.get(user_id_claim)
        User = get_user_model()
        try:
            user = User.objects.get(id=refresh_uid, is_active=True)
        except User.DoesNotExist:
            logger.debug("[RefreshAccessMiddleware] Utilisateur inexistant ou inactif.")
            return self._unauthorized_response("Utilisateur inexistant ou inactif.")

        # Récupérer l'access token
        auth_header = get_authorization_header(request).decode("utf-8")
        if not auth_header or not auth_header.lower().startswith("bearer "):
            logger.debug("[RefreshAccessMiddleware] Access token absent.")
            return self._unauthorized_response("Access token absent.")

        access_token_str = auth_header.split(" ", 1)[1].strip()
        if not access_token_str:
            logger.debug("[RefreshAccessMiddleware] Access token vide.")
            return self._unauthorized_response("Access token vide.")

        # Vérifier syntaxe JWT (décodage sans vérifier expiration)
        try:
            decoded = jwt.decode(
                access_token_str,
                settings.SIMPLE_JWT["SIGNING_KEY"],
                algorithms=[settings.SIMPLE_JWT["ALGORITHM"]],
                options={"verify_exp": False}  # ignore l'expiration
            )
            if str(decoded.get(user_id_claim)) != str(user.id):
                logger.debug("[RefreshAccessMiddleware] Access token non compatible avec refresh.")
                return self._unauthorized_response("Access token invalide pour ce refresh token.")

            # Essayer de créer l'AccessToken pour détecter expiration
            try:
                AccessToken(access_token_str)
                request.user = user
                logger.debug(f"[RefreshAccessMiddleware] Accès autorisé pour {user.email}")
            except TokenError:
                # Token expiré mais syntaxe correcte → rotation
                new_access = str(refresh.access_token)
                request.META["NEW_ACCESS_TOKEN"] = new_access
                request.user = user
                logger.debug(f"[RefreshAccessMiddleware] Nouveau access token généré pour {user.email}")

        except (jwt.DecodeError, jwt.InvalidTokenError):
            # Token mal formé → 401
            logger.debug("[RefreshAccessMiddleware] Access token mal formé ou invalide.")
            return self._unauthorized_response("Access token invalide ou mal formé.")

        except Exception as e:
            logger.exception(f"[RefreshAccessMiddleware] Erreur middleware: {e}")
            return self._unauthorized_response("Erreur serveur.")

    def process_response(self, request, response):
        new_access = getattr(request, "META", {}).get("NEW_ACCESS_TOKEN", None)
        if new_access:
            if hasattr(response, "headers"):
                response.headers["X-New-Access-Token"] = new_access
                existing = response.headers.get("Access-Control-Expose-Headers", "")
                response.headers["Access-Control-Expose-Headers"] = (
                    (existing + ", " if existing else "") + "X-New-Access-Token"
                )
            else:
                response["X-New-Access-Token"] = new_access
                existing = response.get("Access-Control-Expose-Headers", "")
                response["Access-Control-Expose-Headers"] = (
                    (existing + ", " if existing else "") + "X-New-Access-Token"
                )
        return response

    def _unauthorized_response(self, message):
        return JsonResponse({"detail": message}, status=401)
