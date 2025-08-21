# views.py
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework import status, permissions, filters, viewsets
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
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
    "max_age": 7*24*60*60  # 7 jours
})

# -------- Auth --------
class AdminTokenObtainPairView(TokenObtainPairView):
    serializer_class = AdminTokenObtainPairSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        refresh_str = response.data.get("refresh")
        access_str = response.data.get("access")
        if not refresh_str or not access_str:
            return Response({"detail": "Erreur génération tokens."}, status=500)

        # Mettre refresh en cookie HttpOnly
        cfg = JWT_COOKIE_SETTINGS
        response.set_cookie(
            key="refresh_token",
            value=refresh_str,
            httponly=cfg.get("httponly", True),
            secure=cfg.get("secure", False),
            samesite=cfg.get("samesite", "Lax"),
            path=cfg.get("path", "/"),
            max_age=cfg.get("max_age", 7*24*60*60),
        )

        # Mettre access dans header
        response["Authorization"] = f"Bearer {access_str}"
        response.data.pop("refresh", None)
        return response

class AdminUserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = AdminUserSerializer(request.user)
        return Response(serializer.data)

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Supprime uniquement le cookie refresh
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

            # Génère nouveau access token
            new_access = str(old_refresh.access_token)

            # Met à jour cookie refresh (pas de blacklist)
            resp = Response({"access": new_access}, status=200)
            resp["Authorization"] = f"Bearer {new_access}"
            resp.set_cookie("refresh_token", str(old_refresh), **JWT_COOKIE_SETTINGS)

            # Expose headers pour frontend
            expose = resp.get("Access-Control-Expose-Headers", "")
            if "Authorization" not in expose:
                resp["Access-Control-Expose-Headers"] = (expose + ", Authorization").strip(", ")
            if "X-New-Access-Token" not in expose:
                resp["Access-Control-Expose-Headers"] += ", X-New-Access-Token"
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
