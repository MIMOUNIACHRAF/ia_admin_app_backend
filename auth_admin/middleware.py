# middleware.py
from django.utils.deprecation import MiddlewareMixin
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken, TokenError
from rest_framework_simplejwt.authentication import JWTAuthentication

class RefreshAccessMiddleware(MiddlewareMixin):
    """
    Middleware qui tente de rafraîchir automatiquement l'access token
    en lisant le refresh_token dans les cookies si l'access est expiré.
    """
    def process_request(self, request):
        # n'intervenir que pour les routes API si tu veux
        if not request.path.startswith("/api/"):
            return None

        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        if auth_header.startswith("Bearer "):
            token_str = auth_header.split(" ")[1]
            try:
                # valider access token (lancer exception si expiré)
                AccessToken(token_str)
                return None  # access ok
            except TokenError:
                # access invalide/expiré => tenter refresh
                pass

        # pas d'access valide ; tenter de lire refresh cookie
        refresh = request.COOKIES.get("refresh_token")
        if not refresh:
            return None

        try:
            refresh_token = RefreshToken(refresh)
            new_access = str(refresh_token.access_token)

            # Optionnel : si ROTATE_REFRESH_TOKENS=True et BLACKLIST_AFTER_ROTATION=True,
            # on doit utiliser TokenRefreshView qui génère new refresh. Ici on ne rotate pas manuellement.

            # Injecter nouveau header Authorization pour que DRF authenticate le request
            request.META['HTTP_AUTHORIZATION'] = f'Bearer {new_access}'
            # Stocker pour que process_response puisse l'envoyer au client
            request._new_access_token = new_access
        except TokenError:
            # refresh invalide -> ne rien faire
            pass

        return None

    def process_response(self, request, response):
        # si on a généré un nouveau access, l'ajouter au header
        new_access = getattr(request, "_new_access_token", None)
        if new_access:
            response.setdefault('Access-Control-Expose-Headers', '')
            # exposer le header pour frontend
            existing = response['Access-Control-Expose-Headers']
            if 'X-New-Access-Token' not in existing:
                if existing:
                    response['Access-Control-Expose-Headers'] = existing + ', X-New-Access-Token'
                else:
                    response['Access-Control-Expose-Headers'] = 'X-New-Access-Token'
            response['X-New-Access-Token'] = new_access
        return response
