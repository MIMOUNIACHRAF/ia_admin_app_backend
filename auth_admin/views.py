# views.py
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework import status, permissions, filters, viewsets
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from axes.handlers.proxy import AxesProxyHandler
from .serializers import AdminTokenObtainPairSerializer, AdminUserSerializer, AgentIASerializer
from .models import AgentIA
from rest_framework.pagination import PageNumberPagination
import logging

logger = logging.getLogger(__name__)

# -------- Utilitaires --------
def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0]
    return request.META.get("REMOTE_ADDR")

def is_locked(request) -> bool:
    handler = AxesProxyHandler()
    return handler.is_locked(request)

# -------- Auth --------
class AdminTokenObtainPairView(TokenObtainPairView):
    serializer_class = AdminTokenObtainPairSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        ip = get_client_ip(request)
        username = request.data.get("username", "")

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

        # ✅ Ne plus stocker le refresh token dans le cookie ici
        # Frontend React/Netlify s'en occupe désormais

        return Response(
            {
                "access": access_str,
                "refresh": refresh_str
            },
            status=200
        )

# -------- User info --------
class AdminUserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = AdminUserSerializer(request.user)
        return Response(serializer.data)

# -------- Logout --------
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        resp = Response({"detail": "Déconnecté"}, status=200)
        # Optionnel : supprimer le cookie si présent
        resp.delete_cookie("refresh_token")
        return resp

# -------- Refresh token --------
class CustomTokenRefreshView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        # Accept refresh token from body JSON or cookie
        refresh_token = request.data.get("refresh") or request.COOKIES.get("refresh_token")
        if not refresh_token:
            return Response({"detail": "Refresh token absent."}, status=401)
        try:
            old_refresh = RefreshToken(refresh_token)
            user_id = old_refresh.get(settings.SIMPLE_JWT.get("USER_ID_CLAIM", "user_id"))
            User = get_user_model()
            user = User.objects.get(id=user_id, is_active=True)

            # Nouveau access token
            new_access = str(old_refresh.access_token)

            return Response({"access": new_access}, status=200)

        except TokenError:
            return Response({"detail": "Refresh token invalide ou expiré."}, status=401)
        except User.DoesNotExist:
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
