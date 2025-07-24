from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import AdminTokenObtainPairSerializer, AdminUserSerializer
from .models import AdminUser

class AdminTokenObtainPairView(TokenObtainPairView):
    """
    Custom view for obtaining JWT tokens.
    Takes a set of user credentials and returns an access and refresh token.
    """
    serializer_class = AdminTokenObtainPairSerializer
    permission_classes = [AllowAny]

class AdminUserView(APIView):
    """
    View to retrieve the current authenticated user's information.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        Return the authenticated user's details.
        """
        serializer = AdminUserSerializer(request.user)
        return Response(serializer.data)

class LogoutView(APIView):
    """
    View to blacklist the refresh token, effectively logging out the user.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"detail": "Successfully logged out."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)