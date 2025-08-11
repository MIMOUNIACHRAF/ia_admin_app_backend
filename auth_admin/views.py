from django.conf import settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import TokenError
from .serializers import AdminTokenObtainPairSerializer, AdminUserSerializer
from django.core.cache import cache
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed


JWT_COOKIE_SETTINGS = getattr(settings, "JWT_COOKIE_SETTINGS", {
    "httponly": True,
    "secure": False,
    "samesite": "Lax",
    "path": "/",
    "max_age": 7 * 24 * 60 * 60
})


# class AdminTokenObtainPairView(TokenObtainPairView):
#     serializer_class = AdminTokenObtainPairSerializer
#     permission_classes = [AllowAny]

#     def post(self, request, *args, **kwargs):
#         response = super().post(request, *args, **kwargs)
#         refresh_token = response.data.get("refresh")
#         access_token = response.data.get("access")

#         if refresh_token:
#             response.set_cookie(
#                 key="refresh_token",
#                 value=refresh_token,
#                 httponly=JWT_COOKIE_SETTINGS["httponly"],
#                 secure=JWT_COOKIE_SETTINGS["secure"],
#                 samesite=JWT_COOKIE_SETTINGS["samesite"],
#                 path=JWT_COOKIE_SETTINGS["path"],
#                 max_age=JWT_COOKIE_SETTINGS["max_age"],
#             )
#             response.data.pop("refresh", None)

#         if access_token:
#             # Mettre aussi dans le header pour faciliter l'utilisation côté front
#             response["Authorization"] = f"Bearer {access_token}"

#         return response

from django.core.cache import cache
from rest_framework import status
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.permissions import AllowAny

import logging

logger = logging.getLogger(__name__)

class AdminTokenObtainPairView(TokenObtainPairView):
    serializer_class = AdminTokenObtainPairSerializer
    permission_classes = [AllowAny]

    MAX_FAILED_ATTEMPTS = 5
    BLOCK_TIME = 15 * 60  # 15 minutes en secondes

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def post(self, request, *args, **kwargs):
        ip = self.get_client_ip(request)
        logger.debug(f"Tentative de login depuis IP: {ip}")

        blocked_key = f"blocked_{ip}"
        failed_key = f"failed_login_{ip}"

        if cache.get(blocked_key):
            logger.debug(f"IP {ip} bloquée temporairement")
            return Response(
                {"detail": "Trop de tentatives de connexion. Veuillez réessayer dans 15 minutes."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        failed_attempts = cache.get(failed_key, 0)
        logger.debug(f"Tentatives échouées actuelles pour IP {ip}: {failed_attempts}")

        try:
            response = super().post(request, *args, **kwargs)
        except AuthenticationFailed as auth_exc:
            # Cas classique : identifiants invalides
            failed_attempts += 1
            cache.set(failed_key, failed_attempts, timeout=self.BLOCK_TIME)
            logger.error(f"AuthenticationFailed lors login IP {ip}: {auth_exc}")
            logger.debug(f"Login échoué - incrémentation tentative à {failed_attempts} pour IP {ip}")

            if failed_attempts >= self.MAX_FAILED_ATTEMPTS:
                cache.set(blocked_key, True, timeout=self.BLOCK_TIME)
                logger.debug(f"IP {ip} bloquée pendant {self.BLOCK_TIME} secondes")
                return Response(
                    {"detail": "Trop de tentatives de connexion. IP bloquée 15 minutes."},
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )
            return Response({"detail": "Identifiants invalides."}, status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            # Autres erreurs inattendues
            failed_attempts += 1
            cache.set(failed_key, failed_attempts, timeout=self.BLOCK_TIME)
            logger.error(f"Exception lors login IP {ip}: {e}")
            logger.debug(f"Login échoué - incrémentation tentative à {failed_attempts} pour IP {ip}")

            if failed_attempts >= self.MAX_FAILED_ATTEMPTS:
                cache.set(blocked_key, True, timeout=self.BLOCK_TIME)
                logger.debug(f"IP {ip} bloquée pendant {self.BLOCK_TIME} secondes")
                return Response(
                    {"detail": "Trop de tentatives de connexion. IP bloquée 15 minutes."},
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )
            return Response({"detail": "Erreur serveur lors de la connexion."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Si login échoue (status != 200), on traite aussi
        if response.status_code != status.HTTP_200_OK:
            failed_attempts += 1
            cache.set(failed_key, failed_attempts, timeout=self.BLOCK_TIME)
            logger.debug(f"Login échoué - incrémentation tentative à {failed_attempts} pour IP {ip}")

            if failed_attempts >= self.MAX_FAILED_ATTEMPTS:
                cache.set(blocked_key, True, timeout=self.BLOCK_TIME)
                logger.debug(f"IP {ip} bloquée pendant {self.BLOCK_TIME} secondes")
                return Response(
                    {"detail": "Trop de tentatives de connexion. IP bloquée 15 minutes."},
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )
            return response

        # Login réussi, reset compteur
        logger.debug(f"Login réussi pour IP {ip}, reset compteur")
        cache.delete(failed_key)
        cache.delete(blocked_key)

        # Gestion tokens (cookie + header)
        refresh_token = response.data.get("refresh")
        access_token = response.data.get("access")

        if refresh_token:
            response.set_cookie(
                key="refresh_token",
                value=refresh_token,
                httponly=JWT_COOKIE_SETTINGS.get("httponly", True),
                secure=JWT_COOKIE_SETTINGS.get("secure", False),
                samesite=JWT_COOKIE_SETTINGS.get("samesite", "Lax"),
                path=JWT_COOKIE_SETTINGS.get("path", "/"),
                max_age=JWT_COOKIE_SETTINGS.get("max_age", 7 * 24 * 60 * 60),
            )
            response.data.pop("refresh", None)

        if access_token:
            response["Authorization"] = f"Bearer {access_token}"

        return response
class AdminUserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = AdminUserSerializer(request.user)
        return Response(serializer.data)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh = request.COOKIES.get("refresh_token")
        if not refresh:
            return Response({"detail": "Refresh token non trouvé."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = RefreshToken(refresh)
            token.blacklist()
        except TokenError:
            pass

        resp = Response({"detail": "Déconnecté"}, status=status.HTTP_200_OK)
        resp.delete_cookie("refresh_token", path=JWT_COOKIE_SETTINGS["path"])
        return resp


class CustomTokenRefreshView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        refresh_token = request.COOKIES.get("refresh_token")
        if not refresh_token:
            return Response({"detail": "Refresh token absent."}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            refresh = RefreshToken(refresh_token)
            new_access = str(refresh.access_token)

            resp = Response({"access": new_access}, status=status.HTTP_200_OK)
            resp["Authorization"] = f"Bearer {new_access}"

            # Rotation manuelle si nécessaire
            if settings.SIMPLE_JWT.get("ROTATE_REFRESH_TOKENS", False):
                new_refresh = RefreshToken.for_user(request.user)
                resp.set_cookie(
                    key="refresh_token",
                    value=str(new_refresh),
                    httponly=JWT_COOKIE_SETTINGS["httponly"],
                    secure=JWT_COOKIE_SETTINGS["secure"],
                    samesite=JWT_COOKIE_SETTINGS["samesite"],
                    path=JWT_COOKIE_SETTINGS["path"],
                    max_age=JWT_COOKIE_SETTINGS["max_age"],
                )

            return resp

        except TokenError:
            return Response({"detail": "Refresh token invalide."}, status=status.HTTP_401_UNAUTHORIZED)

from rest_framework import viewsets, permissions, filters
from rest_framework.pagination import PageNumberPagination
from .models import AgentIA
from .serializers import AgentIASerializer
from .permissions import IsAdminOrOwner

class StandardResultsSetPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = "page_size"
    max_page_size = 100

class AgentIAViewSet(viewsets.ModelViewSet):
    """
    CRUD complet pour les agents IA avec pagination, recherche et permissions.
    """
    queryset = AgentIA.objects.all().order_by("-date_creation")
    serializer_class = AgentIASerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminOrOwner]
    pagination_class = StandardResultsSetPagination
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['nom', 'description']
    ordering_fields = ['date_creation', 'nom']
    ordering = ['-date_creation']

    def get_queryset(self):
        user = self.request.user
        if user.is_staff:
            return AgentIA.objects.all()
        return AgentIA.objects.filter(proprietaire=user)

    def perform_create(self, serializer):
        print(f"[DEBUG] Création agent pour user {self.request.user.email}")
        serializer.save(proprietaire=self.request.user)
        
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
        except Exception as e:
            print(f"[ERROR CREATE] {e}")
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)