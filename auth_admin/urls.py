from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    AdminTokenObtainPairView,
    AdminUserView,
    LogoutView,
    CustomTokenRefreshView,
    AgentIAViewSet,
)

router = DefaultRouter()
router.register(r'agents', AgentIAViewSet, basename='agents')

urlpatterns = [
    # Authentification
    path("auth/login/", AdminTokenObtainPairView.as_view(), name="admin_login"),
    path("auth/me/", AdminUserView.as_view(), name="admin_user"),
    path("auth/logout/", LogoutView.as_view(), name="admin_logout"),
    path("auth/refresh/", CustomTokenRefreshView.as_view(), name="token_refresh_cookie"),

    # API agents IA
    path("V1/", include(router.urls)),
]
