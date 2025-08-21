from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import AdminUser, AgentIA, QuestionReponse
import uuid


class AdminTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Custom JWT token serializer :
    - Ajoute un SID unique
    - Ajoute l'email
    """

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token["sid"] = uuid.uuid4().hex  # Session ID unique
        token["email"] = user.email
        return token

    def validate(self, attrs):
        data = super().validate(attrs)
        data["email"] = self.user.email
        data["is_superuser"] = self.user.is_superuser
        return data


class AdminUserSerializer(serializers.ModelSerializer):
    """Serializer simple pour AdminUser"""

    class Meta:
        model = AdminUser
        fields = ["id", "email", "is_superuser"]
        read_only_fields = ["id", "is_superuser"]


class QuestionReponseSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(required=False)

    class Meta:
        model = QuestionReponse
        fields = ["id", "question", "reponse"]

    def validate(self, data):
        question = data.get("question", "").strip()
        reponse = data.get("reponse", "").strip()
        if not question:
            raise serializers.ValidationError("La question ne peut pas être vide.")
        if not reponse:
            raise serializers.ValidationError("La réponse ne peut pas être vide.")
        return data


class AgentIASerializer(serializers.ModelSerializer):
    questions_reponses = QuestionReponseSerializer(many=True, required=False)

    class Meta:
        model = AgentIA
        fields = ["id", "nom", "description", "type_agent", "actif", "questions_reponses"]
        read_only_fields = ["id"]

    def validate_type_agent(self, value: str) -> str:
        if value not in dict(AgentIA.AGENT_TYPES).keys():
            raise serializers.ValidationError("Type d'agent invalide.")
        return value

    def validate_nom(self, value: str) -> str:
        if not value.strip():
            raise serializers.ValidationError("Le nom de l'agent ne peut pas être vide.")
        return value

    def create(self, validated_data: dict) -> AgentIA:
        q_and_a_data = validated_data.pop("questions_reponses", [])
        agent = AgentIA.objects.create(**validated_data)

        for qa_data in q_and_a_data:
            QuestionReponse.objects.create(agent=agent, **qa_data)
        return agent

    def update(self, instance: AgentIA, validated_data: dict) -> AgentIA:
        q_and_a_data = validated_data.pop("questions_reponses", None)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        if q_and_a_data is not None:
            existing_ids = [qa.id for qa in instance.questions_reponses.all()]
            sent_ids = [qa.get("id") for qa in q_and_a_data if qa.get("id")]

            to_delete = set(existing_ids) - set(sent_ids)
            if to_delete:
                QuestionReponse.objects.filter(id__in=to_delete).delete()

            for qa_data in q_and_a_data:
                qa_id = qa_data.get("id")
                if qa_id:
                    QuestionReponse.objects.filter(id=qa_id, agent=instance).update(
                        question=qa_data.get("question", "").strip(),
                        reponse=qa_data.get("reponse", "").strip(),
                    )
                else:
                    QuestionReponse.objects.create(agent=instance, **qa_data)

        return instance
