from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import AdminUser

class AdminTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Custom JWT token serializer that adds the user's email to the token payload.
    """
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Add custom claims
        token['email'] = user.email

        return token

    def validate(self, attrs):
        """
        Override the validate method to customize the response data.
        """
        data = super().validate(attrs)

        # Add extra response data if needed
        data['email'] = self.user.email
        data['is_superuser'] = self.user.is_superuser

        return data

class AdminUserSerializer(serializers.ModelSerializer):
    """
    Serializer for the AdminUser model.
    """
    class Meta:
        model = AdminUser
        fields = ['id', 'email', 'is_superuser']
        read_only_fields = ['id', 'is_superuser']