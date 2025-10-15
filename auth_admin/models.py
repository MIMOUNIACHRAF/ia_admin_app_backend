from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone
from django.conf import settings
class AdminUserManager(BaseUserManager):
    def create_user(self, email, password=None):
        """
        Creates and saves a User with the given email and password.
        """
        if not email:
            raise ValueError("L'email est requis")

        user = self.model(
            email=self.normalize_email(email),
        )

        user.set_password(password)
        user.is_staff = True
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password):
        """
        Creates and saves a superuser with the given email and password.
        """
        user = self.create_user(
            email=email,
            password=password,
        )
        user.is_superuser = True
        user.save(using=self._db)
        return user

class AdminUser(AbstractBaseUser, PermissionsMixin):
    """
    Custom user model that uses email as the unique identifier instead of username.
    """
    email = models.EmailField(
        verbose_name='email address',
        max_length=255,
        unique=True,
    )
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=True)

    objects = AdminUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []  # Email is already required by default

    def __str__(self):
        return self.email

    def get_full_name(self):
        return self.email

    def get_short_name(self):
        return self.email
    
class Template(models.Model):
    """
    Template regroupant plusieurs QuestionReponse réutilisables.
    """
    nom = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True)
    date_creation = models.DateTimeField(default=timezone.now)
    date_modification = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.nom


class AgentIA(models.Model):
    TRADITIONNEL = 'trad'
    LLM = 'llm'
    AGENT_TYPES = [
        (TRADITIONNEL, 'Agent traditionnel'),
        (LLM, 'Agent LLM'),
    ]

    nom = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True)
    type_agent = models.CharField(max_length=10, choices=AGENT_TYPES)
    proprietaire = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='agents')
    actif = models.BooleanField(default=True)
    templates = models.ManyToManyField(Template, blank=True, related_name='agents')
    date_creation = models.DateTimeField(auto_now_add=True)
    date_modification = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-date_creation']

    def __str__(self):
        return self.nom


class QuestionReponse(models.Model):
    """
    QuestionReponse unified model:
    - Either attached to an Agent (agent != None) -> custom Q/R for agent
    - Or attached to a Template (template != None) -> reusable Q/R
    - Constraint must be enforced in serializers/validators: one of agent or template must be set, not both.
    """
    agent = models.ForeignKey(AgentIA, on_delete=models.CASCADE, related_name='questions_reponses', null=True, blank=True)
    template = models.ForeignKey(Template, on_delete=models.CASCADE, related_name='questions_reponses', null=True, blank=True)
    question = models.TextField()
    reponse = models.TextField()
    ordre = models.PositiveIntegerField(default=0)

    date_creation = models.DateTimeField(default=timezone.now)
    date_modification = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=['question']),
        ]
        ordering = ['ordre', '-date_creation']

    def clean(self):
        # optional: enforce in Python side if you use full_clean()
        if bool(self.agent) == bool(self.template):
            # both set or both not set => invalid
            raise ValueError("QuestionReponse doit appartenir soit à un agent soit à un template (exactement un).")

    def __str__(self):
        owner = f"Agent:{self.agent_id}" if self.agent_id else f"Template:{self.template_id}"
        return f"[{owner}] Q: {self.question[:50]}"
    
    
    
    
class FailedLoginAttempt(models.Model):
    ip_address = models.GenericIPAddressField(unique=True, db_index=True)
    attempts = models.PositiveSmallIntegerField(default=0)
    blocked_until = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def is_blocked(self):
        return self.blocked_until and self.blocked_until > timezone.now()

    def __str__(self):
        return f"{self.ip_address} ({self.attempts})"
