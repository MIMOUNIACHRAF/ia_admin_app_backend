from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import AdminTokenObtainPairView, AdminUserView, LogoutView

urlpatterns = [
    # JWT Authentication endpoints
    path('auth/login/', AdminTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('auth/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/me/', AdminUserView.as_view(), name='user_info'),
    path('auth/logout/', LogoutView.as_view(), name='auth_logout'),
]