# ia_app/views.py
from django.conf import settings
from rest_framework import status, permissions, filters, viewsets
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from axes.handlers.proxy import AxesProxyHandler
from .serializers import AdminTokenObtainPairSerializer, AdminUserSerializer, AgentIASerializer, TemplateSerializer, QuestionReponseSerializer
from .models import AgentIA, Template, QuestionReponse
from rest_framework.pagination import PageNumberPagination
import logging

from rest_framework.decorators import action
from .services import find_best_local_match

logger = logging.getLogger(__name__)

def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0]
    return request.META.get("REMOTE_ADDR")

def is_locked(request) -> bool:
    handler = AxesProxyHandler()
    return handler.is_locked(request)

class AdminTokenObtainPairView(TokenObtainPairView):
    serializer_class = AdminTokenObtainPairSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        ip = get_client_ip(request)
        username = request.data.get("username", "")

        if is_locked(request):
            return Response({"detail": "Trop de tentatives de connexion. Veuillez réessayer plus tard."}, status=status.HTTP_403_FORBIDDEN)

        response = super().post(request, *args, **kwargs)
        if response.status_code != 200:
            logger.warning(f"Login failed for {username} from IP {ip}")
            return response

        refresh_str = response.data.get("refresh")
        access_str = response.data.get("access")
        if not refresh_str or not access_str:
            return Response({"detail": "Erreur génération tokens."}, status=500)

        return Response({"access": access_str, "refresh": refresh_str}, status=200)

class QuestionReponseViewSet(viewsets.ModelViewSet):
    queryset = QuestionReponse.objects.all().order_by("ordre", "-date_creation")
    serializer_class = QuestionReponseSerializer
    permission_classes = [IsAuthenticated]
class AdminUserView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        serializer = AdminUserSerializer(request.user)
        return Response(serializer.data)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        resp = Response({"detail": "Déconnecté"}, status=200)
        resp.delete_cookie("refresh_token")
        return resp


class CustomTokenRefreshView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        refresh_token = (
            request.data.get("refresh") or
            request.COOKIES.get("refresh_token") or
            request.headers.get("X-Refresh-Token")
        )
        if not refresh_token:
            return Response({"detail": "Refresh token absent."}, status=401)
        try:
            refresh = RefreshToken(refresh_token)
            new_access = str(refresh.access_token)
            return Response({"access": new_access}, status=200)
        except TokenError as e:
            return Response({"detail": f"Refresh expiré ou invalide: {str(e)}"}, status=401)


# Pagination class
class StandardResultsSetPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = "page_size"
    max_page_size = 100


class TemplateViewSet(viewsets.ModelViewSet):
    queryset = Template.objects.all().order_by("-date_creation")
    serializer_class = TemplateSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = StandardResultsSetPagination
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["nom", "description"]
    ordering_fields = ["date_creation", "nom"]
    ordering = ["-date_creation"]


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

    @action(detail=True, methods=["post"], url_path="assign-template")
    def assign_template(self, request, pk=None):
        agent = self.get_object()
        template_id = request.data.get("template_id")
        if not template_id:
            return Response({"detail": "template_id requis."}, status=400)
        try:
            template = Template.objects.get(id=template_id)
            agent.templates.add(template)
            return Response({"detail": "Template assigné."}, status=200)
        except Template.DoesNotExist:
            return Response({"detail": "Template introuvable."}, status=404)

    @action(detail=True, methods=["post"], url_path="unassign-template")
    def unassign_template(self, request, pk=None):
        agent = self.get_object()
        template_id = request.data.get("template_id")
        if not template_id:
            return Response({"detail": "template_id requis."}, status=400)
        try:
            template = Template.objects.get(id=template_id)
            agent.templates.remove(template)
            return Response({"detail": "Template retiré."}, status=200)
        except Template.DoesNotExist:
            return Response({"detail": "Template introuvable."}, status=404)

    @action(detail=True, methods=["post"], url_path="match", permission_classes=[permissions.IsAuthenticated])
    def match_local(self, request, pk=None):
        """
        Matching local:
        - Cherche dans questions personnalisées (agent)
        - Sinon dans templates associés
        - Retourne la réponse locale si trouvée, sinon source 'llm' pour fallback
        """
        agent = self.get_object()
        user_question = (request.data.get("question") or "").strip()
        threshold = float(request.data.get("threshold", 0.6))

        if not user_question:
            return Response({"detail": "Question manquante."}, status=400)

        result = find_best_local_match(agent, user_question, threshold=threshold)
        if result:
            qr_obj, score = result
            return Response({
                "source": "local",
                "matched_question": qr_obj.question,
                "response": qr_obj.reponse,
                "score": score
            }, status=200)
        # no local match
        return Response({"source": "llm", "detail": "Aucun match local trouvé."}, status=204)
