from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models

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
    
    
from django.conf import settings
from django.db import models

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
    date_creation = models.DateTimeField(auto_now_add=True)
    date_modification = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-date_creation']

    def __str__(self):
        return self.nom


class QuestionReponse(models.Model):
    agent = models.ForeignKey(AgentIA, on_delete=models.CASCADE, related_name='questions_reponses')
    question = models.TextField()
    reponse = models.TextField()

    def __str__(self):
        return f"Q: {self.question[:50]}"
