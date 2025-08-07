from django.urls import path
from .views import (
    AdminTokenObtainPairView,
    AdminUserView,
    LogoutView,
    CustomTokenRefreshView
)

urlpatterns = [
    path("auth/login/", AdminTokenObtainPairView.as_view(), name="admin_login"),
    path("auth/me/", AdminUserView.as_view(), name="admin_user"),
    path("auth/logout/", LogoutView.as_view(), name="admin_logout"),
    path("auth/refresh/", CustomTokenRefreshView.as_view(), name="token_refresh_cookie"),
]
