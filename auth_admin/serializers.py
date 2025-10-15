# ia_app/serializers.py
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import AdminUser, AgentIA, Template, QuestionReponse
import uuid

class AdminTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token["sid"] = uuid.uuid4().hex
        token["email"] = getattr(user, "email", "")
        return token

    def validate(self, attrs):
        data = super().validate(attrs)
        data["email"] = getattr(self.user, "email", "")
        data["is_superuser"] = getattr(self.user, "is_superuser", False)
        return data

class AdminUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = AdminUser
        fields = ["id", "email", "is_superuser"]
        read_only_fields = ["id", "is_superuser"]


class QuestionReponseSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(required=False)

    class Meta:
        model = QuestionReponse
        fields = ["id", "question", "reponse", "ordre", "agent", "template"]
        read_only_fields = ["id"]
        extra_kwargs = {
            "agent": {"required": False, "allow_null": True},
            "template": {"required": False, "allow_null": True},
        }

    def validate(self, data):
        question = data.get("question", "").strip()
        reponse = data.get("reponse", "").strip()
        agent = data.get("agent", None)
        template = data.get("template", None)

        if not question:
            raise serializers.ValidationError("La question ne peut pas être vide.")
        if not reponse:
            raise serializers.ValidationError("La réponse ne peut pas être vide.")

        # ensure either agent xor template
        if (agent is None and template is None) or (agent is not None and template is not None):
            raise serializers.ValidationError("QuestionReponse doit appartenir soit à un agent, soit à un template (exactement un).")

        return data


class TemplateSerializer(serializers.ModelSerializer):
    questions_reponses = QuestionReponseSerializer(many=True, required=False)

    class Meta:
        model = Template
        fields = ["id", "nom", "description", "questions_reponses", "date_creation", "date_modification"]
        read_only_fields = ["id", "date_creation", "date_modification"]

    def create(self, validated_data):
        qrs = validated_data.pop("questions_reponses", [])
        template = Template.objects.create(**validated_data)
        for qr in qrs:
            # force template relation
            qr_obj = QuestionReponse.objects.create(template=template, **{
                "question": qr["question"].strip(),
                "reponse": qr["reponse"].strip(),
                "ordre": qr.get("ordre", 0),
            })
        return template

    def update(self, instance, validated_data):
        qrs = validated_data.pop("questions_reponses", None)
        for attr, val in validated_data.items():
            setattr(instance, attr, val)
        instance.save()

        if qrs is not None:
            # synchronize questions: basic approach - delete missing, update existing, create new
            existing = {qr.id: qr for qr in instance.questions_reponses.all()}
            sent_ids = [qr.get("id") for qr in qrs if qr.get("id")]

            # delete removed
            to_delete = [eid for eid in existing.keys() if eid not in sent_ids]
            if to_delete:
                QuestionReponse.objects.filter(id__in=to_delete).delete()

            for qr in qrs:
                qr_id = qr.get("id")
                if qr_id and qr_id in existing:
                    QuestionReponse.objects.filter(id=qr_id, template=instance).update(
                        question=qr["question"].strip(),
                        reponse=qr["reponse"].strip(),
                        ordre=qr.get("ordre", 0)
                    )
                else:
                    QuestionReponse.objects.create(template=instance, question=qr["question"].strip(), reponse=qr["reponse"].strip(), ordre=qr.get("ordre", 0))
        return instance


class AgentIASerializer(serializers.ModelSerializer):
    questions_reponses = QuestionReponseSerializer(many=True, required=False)
    template_ids = serializers.ListField(child=serializers.IntegerField(), write_only=True, required=False)
    templates = TemplateSerializer(many=True, read_only=True)

    class Meta:
        model = AgentIA
        fields = ["id", "nom", "description", "type_agent", "actif", "templates", "template_ids", "questions_reponses", "date_creation", "date_modification"]
        read_only_fields = ["id", "templates", "date_creation", "date_modification"]

    def validate_type_agent(self, value: str) -> str:
        if value not in dict(AgentIA.AGENT_TYPES).keys():
            raise serializers.ValidationError("Type d'agent invalide.")
        return value

    def validate_nom(self, value: str) -> str:
        if not value.strip():
            raise serializers.ValidationError("Le nom de l'agent ne peut pas être vide.")
        return value

    def create(self, validated_data):
        q_and_a = validated_data.pop("questions_reponses", [])
        template_ids = validated_data.pop("template_ids", [])
        agent = AgentIA.objects.create(**validated_data)
        if template_ids:
            templates = Template.objects.filter(id__in=template_ids)
            agent.templates.set(templates)
        for qa in q_and_a:
            QuestionReponse.objects.create(agent=agent, question=qa["question"].strip(), reponse=qa["reponse"].strip(), ordre=qa.get("ordre", 0))
        return agent

    def update(self, instance, validated_data):
        q_and_a = validated_data.pop("questions_reponses", None)
        template_ids = validated_data.pop("template_ids", None)

        for attr, val in validated_data.items():
            setattr(instance, attr, val)
        instance.save()

        if template_ids is not None:
            templates = Template.objects.filter(id__in=template_ids)
            instance.templates.set(templates)

        if q_and_a is not None:
            existing = {qa.id: qa for qa in instance.questions_reponses.all()}
            sent_ids = [qa.get("id") for qa in q_and_a if qa.get("id")]
            to_delete = [eid for eid in existing.keys() if eid not in sent_ids]
            if to_delete:
                QuestionReponse.objects.filter(id__in=to_delete).delete()

            for qa in q_and_a:
                qa_id = qa.get("id")
                if qa_id and qa_id in existing:
                    QuestionReponse.objects.filter(id=qa_id, agent=instance).update(
                        question=qa["question"].strip(),
                        reponse=qa["reponse"].strip(),
                        ordre=qa.get("ordre", 0)
                    )
                else:
                    QuestionReponse.objects.create(agent=instance, question=qa["question"].strip(), reponse=qa["reponse"].strip(), ordre=qa.get("ordre", 0))
        return instance
