from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django.core.exceptions import ValidationError
from django import forms

from .models import AdminUser, AgentIA, QuestionReponse

# -------- Forms Utilisateurs --------
class UserCreationForm(forms.ModelForm):
    """Formulaire pour créer un nouvel utilisateur."""
    password1 = forms.CharField(label='Password', widget=forms.PasswordInput)
    password2 = forms.CharField(label='Password confirmation', widget=forms.PasswordInput)

    class Meta:
        model = AdminUser
        fields = ('email',)

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise ValidationError("Passwords don't match")
        return password2

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user

class UserChangeForm(forms.ModelForm):
    """Formulaire pour modifier un utilisateur existant."""
    password = ReadOnlyPasswordHashField()

    class Meta:
        model = AdminUser
        fields = ('email', 'password', 'is_active', 'is_staff', 'is_superuser')

# -------- Admin Utilisateurs --------
class UserAdmin(BaseUserAdmin):
    form = UserChangeForm
    add_form = UserCreationForm
    list_display = ('email', 'is_staff')
    list_filter = ('is_superuser',)
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2'),
        }),
    )
    search_fields = ('email',)
    ordering = ('email',)
    filter_horizontal = ('groups', 'user_permissions',)

admin.site.register(AdminUser, UserAdmin)

# -------- Admin AgentIA --------
class QuestionReponseInline(admin.TabularInline):
    model = QuestionReponse
    extra = 1

@admin.register(AgentIA)
class AgentIAAdmin(admin.ModelAdmin):
    list_display = ('nom', 'type_agent', 'actif', 'proprietaire', 'date_creation')
    inlines = [QuestionReponseInline]

@admin.register(QuestionReponse)
class QuestionReponseAdmin(admin.ModelAdmin):
    list_display = ('question', 'agent')

# -------- Astuce pour django-axes --------
# Ne jamais réenregistrer AccessAttempt et AccessLog directement
# car ils sont déjà enregistrés par axes.admin pour éviter AlreadyRegistered.
# Si tu veux personnaliser leur affichage, utilise AppConfig.ready() et unregister/register.
