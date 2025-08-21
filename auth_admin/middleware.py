# auth_admin/middleware.py
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework.authentication import get_authorization_header
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from django.http import JsonResponse
import logging

logger = logging.getLogger(__name__)

class RefreshAccessMiddleware(MiddlewareMixin):
    """
    Middleware strict mais avec rotation:
    - Access token requis
    - Vérifie correspondance avec refresh token
    - Vérifie la syntaxe de l'access token
    - Si expiré mais valide avec refresh → génère nouveau access token
    """

    def process_request(self, request):
        # Préflight CORS
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

        try:
            refresh = RefreshToken(refresh_cookie)

            user_id_claim = settings.SIMPLE_JWT.get("USER_ID_CLAIM", "user_id")
            refresh_uid = refresh.get(user_id_claim)
            User = get_user_model()
            user = User.objects.get(id=refresh_uid, is_active=True)

            # Access token depuis l'en-tête
            auth_header = get_authorization_header(request).decode("utf-8")
            if not auth_header or not auth_header.lower().startswith("bearer "):
                logger.debug("[RefreshAccessMiddleware] Access token absent.")
                return self._unauthorized_response("Access token absent.")

            access_token_str = auth_header.split(" ", 1)[1].strip()
            if not access_token_str:
                logger.debug("[RefreshAccessMiddleware] Access token vide.")
                return self._unauthorized_response("Access token vide.")

            # --- Vérification syntaxe access token ---
            valid_syntax, message = self._verify_access_token_syntax(access_token_str)
            if not valid_syntax:
                logger.debug(f"[RefreshAccessMiddleware] {message}")
                return self._unauthorized_response(message)

            try:
                access = AccessToken(access_token_str)
                if str(access.get(user_id_claim)) != str(user.id):
                    logger.debug("[RefreshAccessMiddleware] Access token non compatible avec refresh.")
                    return self._unauthorized_response("Access token invalide pour ce refresh token.")
                # Access token valide → on continue
                request.user = user
                logger.debug(f"[RefreshAccessMiddleware] Accès autorisé pour {user.email}")

            except TokenError:
                # Access token expiré → rotation
                new_access = str(refresh.access_token)
                request.META["NEW_ACCESS_TOKEN"] = new_access
                request.user = user
                logger.debug(f"[RefreshAccessMiddleware] Nouveau access token généré pour {user.email}")

        except (TokenError, User.DoesNotExist):
            logger.debug("[RefreshAccessMiddleware] Token invalide/expiré ou utilisateur inactif.")
            return self._unauthorized_response("Token invalide/expiré ou utilisateur inactif.")
        except Exception as e:
            logger.exception(f"[RefreshAccessMiddleware] Erreur middleware: {e}")
            return self._unauthorized_response("Erreur serveur.")

    def process_response(self, request, response):
        # Ajoute le nouveau access token dans le header si généré
        new_access = getattr(request, "META", {}).get("NEW_ACCESS_TOKEN", None)
        if new_access:
            existing = response.get("Access-Control-Expose-Headers", "")
            headers = (existing + ", " if existing else "") + "X-New-Access-Token"
            response["Access-Control-Expose-Headers"] = headers
            response["X-New-Access-Token"] = new_access
        return response

    def _verify_access_token_syntax(self, token_str):
        """
        Vérifie la syntaxe d'un access token JWT.
        :param token_str: chaîne du token JWT (sans "Bearer ")
        :return: tuple (bool, message)
        """
        if not token_str:
            return False, "Access token vide."
        try:
            AccessToken(token_str)
            return True, "Access token syntaxe correcte."
        except (TokenError, InvalidToken) as e:
            return False, f"Access token invalide ou mal formé: {str(e)}"
        except Exception as e:
            return False, f"Erreur lors de la vérification du token: {str(e)}"

    def _unauthorized_response(self, message):
        return JsonResponse({"detail": message}, status=401)
