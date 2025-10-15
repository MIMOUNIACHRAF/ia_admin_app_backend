# ia_app/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    AdminTokenObtainPairView,
    AdminUserView,
    LogoutView,
    CustomTokenRefreshView,
    AgentIAViewSet,
    TemplateViewSet,
    QuestionReponseViewSet
)

router = DefaultRouter()
router.register(r'agents', AgentIAViewSet, basename='agents')
router.register(r'templates', TemplateViewSet, basename='templates')
router.register(r'questions_reponses', QuestionReponseViewSet, basename='questions_reponses')

urlpatterns = [
    # Auth
    path("auth/login/", AdminTokenObtainPairView.as_view(), name="admin_login"),
    path("auth/me/", AdminUserView.as_view(), name="admin_user"),
    path("auth/logout/", LogoutView.as_view(), name="admin_logout"),
    path("auth/refresh/", CustomTokenRefreshView.as_view(), name="token_refresh_cookie"),

    # API v1
    path("V1/", include(router.urls)),
]
