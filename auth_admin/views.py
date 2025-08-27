# views.py
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework import status, permissions, filters, viewsets
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from axes.handlers.proxy import AxesProxyHandler  # nouveau
from .serializers import AdminTokenObtainPairSerializer, AdminUserSerializer, AgentIASerializer
from .models import AgentIA
from rest_framework.pagination import PageNumberPagination
import logging

logger = logging.getLogger(__name__)

JWT_COOKIE_SETTINGS = getattr(settings, "JWT_COOKIE_SETTINGS", {
    "httponly": True,
    "secure": not settings.DEBUG,
    "samesite": "Lax",
    "path": "/",
    "max_age": 7*24*60*60,
})

# -------- Utilitaires --------
def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0]
    return request.META.get("REMOTE_ADDR")

def is_locked(request) -> bool:
    """
    Vérifie si la requête est bloquée par django-axes (Axes 8+).
    """
    handler = AxesProxyHandler()
    return handler.is_locked(request)

# -------- Auth --------
class AdminTokenObtainPairView(TokenObtainPairView):
    serializer_class = AdminTokenObtainPairSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        ip = get_client_ip(request)
        username = request.data.get("username", "")

        # Vérifie si la requête est bloquée par Axes
        if is_locked(request):
            return Response(
                {"detail": "Trop de tentatives de connexion. Veuillez réessayer plus tard."},
                status=status.HTTP_403_FORBIDDEN
            )

        response = super().post(request, *args, **kwargs)

        if response.status_code != 200:
            logger.warning(f"Login failed for {username} from IP {ip}")
            return response

        refresh_str = response.data.get("refresh")
        access_str = response.data.get("access")
        if not refresh_str or not access_str:
            return Response({"detail": "Erreur génération tokens."}, status=500)

        cfg = JWT_COOKIE_SETTINGS
        response.set_cookie(
            key="refresh_token",
            value=refresh_str,
            httponly=True,
            secure=not settings.DEBUG,   # HTTPS obligatoire seulement en prod
            samesite="Lax",              # compatible localhost
            path="/",
            max_age=7*24*60*60,
        )
        response["Authorization"] = f"Bearer {access_str}"
        response.data.pop("refresh", None)
        response["Access-Control-Expose-Headers"] = "Authorization, X-New-Access-Token"

        return response

# -------- Le reste du code (AdminUserView, LogoutView, CustomTokenRefreshView, AgentIAViewSet) reste identique --------


class AdminUserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = AdminUserSerializer(request.user)
        return Response(serializer.data)

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        resp = Response({"detail": "Déconnecté"}, status=200)
        resp.delete_cookie("refresh_token", path=JWT_COOKIE_SETTINGS.get("path", "/"))
        return resp

class CustomTokenRefreshView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        refresh_cookie = request.COOKIES.get("refresh_token")
        if not refresh_cookie:
            return Response({"detail": "Refresh token absent."}, status=401)
        try:
            old_refresh = RefreshToken(refresh_cookie)
            user_id = old_refresh.get(settings.SIMPLE_JWT.get("USER_ID_CLAIM", "user_id"))
            User = get_user_model()
            user = User.objects.get(id=user_id, is_active=True)

            new_access = str(old_refresh.access_token)

            resp = Response({"access": new_access}, status=200)
            resp["Authorization"] = f"Bearer {new_access}"
            resp.set_cookie("refresh_token", str(old_refresh), **JWT_COOKIE_SETTINGS)
            resp["Access-Control-Expose-Headers"] = "Authorization, X-New-Access-Token"

            return resp
        except TokenError:
            return Response({"detail": "Refresh token invalide ou expiré."}, status=401)
        except get_user_model().DoesNotExist:
            return Response({"detail": "Utilisateur introuvable ou inactif."}, status=401)
        except Exception as e:
            logger.exception(f"Erreur refresh: {e}")
            return Response({"detail": "Erreur serveur."}, status=500)

# -------- Agent IA CRUD --------
class StandardResultsSetPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = "page_size"
    max_page_size = 100

class AgentIAViewSet(viewsets.ModelViewSet):
    queryset = AgentIA.objects.all().order_by("-date_creation")
    serializer_class = AgentIASerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = StandardResultsSetPagination
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["nom", "description"]
    ordering_fields = ["date_creation", "nom"]
    ordering = ["-date_creation"]

    def get_queryset(self):
        user = self.request.user
        return AgentIA.objects.all() if user.is_staff else AgentIA.objects.filter(proprietaire=user)

    def perform_create(self, serializer):
        serializer.save(proprietaire=self.request.user)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
        except Exception as e:
            logger.exception(f"[ERROR CREATE] {e}")
            return Response({"detail": str(e)}, status=400)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=201, headers=headers)
