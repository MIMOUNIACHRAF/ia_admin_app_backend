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
    Middleware pour rotation automatique d'Access Token.
    - Vérifie d'abord refresh_token en cookie HttpOnly
    - Si absent, tente de le récupérer via le header `X-Refresh-Token`
    - Si access token expiré ou absent → nouveau généré depuis refresh token
    """

    def process_request(self, request):
        if request.method == "OPTIONS":
            return

        path = request.path
        public_paths = ["/api/auth/login/", "/api/auth/refresh/", "/api/auth/logout/", "/admin/"]
        if any(path.startswith(p) for p in public_paths):
            return

        # 1️⃣ Vérifier refresh_token d'abord en cookie, sinon en header
        refresh_cookie = request.COOKIES.get("refresh_token")
        refresh_header = request.headers.get("X-Refresh-Token")
        refresh_token = refresh_cookie or refresh_header

        if not refresh_token:
            logger.debug("[RefreshAccessMiddleware] Refresh token absent.")
            return self._unauthorized_response("Refresh token absent ou expiré.")

        try:
            refresh = RefreshToken(refresh_token)
        except TokenError:
            logger.debug("[RefreshAccessMiddleware] Refresh token invalide ou expiré.")
            return self._unauthorized_response("Refresh token invalide ou expiré.")

        # 2️⃣ Identifier l'utilisateur
        user_id_claim = settings.SIMPLE_JWT.get("USER_ID_CLAIM", "user_id")
        refresh_uid = refresh.get(user_id_claim)
        User = get_user_model()
        try:
            user = User.objects.get(id=refresh_uid, is_active=True)
        except User.DoesNotExist:
            logger.debug("[RefreshAccessMiddleware] Utilisateur inexistant ou inactif.")
            return self._unauthorized_response("Utilisateur inexistant ou inactif.")

        # 3️⃣ Vérifier access token (Authorization: Bearer <token>)
        auth_header_bytes = get_authorization_header(request)
        auth_header = auth_header_bytes.decode("utf-8") if auth_header_bytes else None
        access_token_str = (
            auth_header.split(" ", 1)[1].strip()
            if auth_header and auth_header.lower().startswith("bearer ")
            else None
        )

        try:
            if access_token_str:
                decoded = jwt.decode(
                    access_token_str,
                    settings.SIMPLE_JWT["SIGNING_KEY"],
                    algorithms=[settings.SIMPLE_JWT["ALGORITHM"]],
                    options={"verify_exp": False}
                )
                if str(decoded.get(user_id_claim)) != str(user.id):
                    return self._unauthorized_response("Access token invalide pour ce refresh token.")

                try:
                    AccessToken(access_token_str)
                    request.user = user
                    logger.debug(f"[RefreshAccessMiddleware] Accès autorisé pour {user.email}")
                except TokenError:
                    # Token expiré → rotation
                    new_access = str(refresh.access_token)
                    request.META["NEW_ACCESS_TOKEN"] = new_access
                    request.user = user
                    logger.debug(f"[RefreshAccessMiddleware] Nouveau access token généré pour {user.email}")
            else:
                # Aucun access token → nouveau depuis refresh
                new_access = str(refresh.access_token)
                request.META["NEW_ACCESS_TOKEN"] = new_access
                request.user = user
                logger.debug(f"[RefreshAccessMiddleware] Access token absent → nouveau généré pour {user.email}")

        except (jwt.DecodeError, jwt.InvalidTokenError):
            return self._unauthorized_response("Access token mal formé ou invalide.")
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
