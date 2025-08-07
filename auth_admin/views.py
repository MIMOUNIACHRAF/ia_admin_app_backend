from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError

from .serializers import AdminTokenObtainPairSerializer, AdminUserSerializer


class AdminTokenObtainPairView(TokenObtainPairView):
    """
    Custom view for obtaining JWT tokens.
    Puts refresh token in HttpOnly cookie.
    """
    serializer_class = AdminTokenObtainPairSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        refresh_token = response.data.get("refresh")

        if refresh_token:
            # Set refresh token in HttpOnly cookie
            response.set_cookie(
                key="refresh_token",
                value=refresh_token,
                httponly=True,
                secure=False,  # 🔁 False en local, True en prod (HTTPS)
                samesite="Lax",
                path="/",
                max_age=7 * 24 * 60 * 60  # 7 jours
            )

            # Remove refresh token from response body
            response.data.pop("refresh", None)

        return response


class AdminUserView(APIView):
    """
    View to retrieve the current authenticated user's information.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = AdminUserSerializer(request.user)
        return Response(serializer.data)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        print("Cookies reçus :", request.COOKIES)

        refresh_token = request.COOKIES.get("refresh_token")
        if not refresh_token:
            return Response({"detail": "Refresh token not found in cookies."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()

            response = Response({"detail": "Successfully logged out."}, status=status.HTTP_200_OK)
            response.delete_cookie("refresh_token")
            return response

        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)



class CustomTokenRefreshView(APIView):
    """
    Custom view to refresh access token using refresh_token from cookie.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        refresh_token = request.COOKIES.get('refresh_token')

        if not refresh_token:
            return Response({"detail": "Refresh token not provided."}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            token = RefreshToken(refresh_token)
            new_access = str(token.access_token)
            new_refresh = str(token)  # Optionnel : renouveler le refresh token aussi

            # Réponse avec nouveau access_token
            response = Response({
                "access": new_access,
                "refresh": new_refresh  # Optionnel (à retirer si non voulu)
            }, status=status.HTTP_200_OK)

            # Optionnel : mettre à jour le refresh_token dans le cookie
            response.set_cookie(
                key="refresh_token",
                value=new_refresh,
                httponly=True,
                secure=False,  # 🔁 False en local, True en prod (HTTPS)
                samesite='Lax',
                path='/',
                max_age=7 * 24 * 60 * 60
            )

            return response

        except TokenError:
            return Response({"detail": "Invalid refresh token."}, status=status.HTTP_401_UNAUTHORIZED)
