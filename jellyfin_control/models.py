from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
import uuid
from django.utils import timezone
from django.conf import settings

class Function(models.Model):
    name = models.CharField(max_length=255, unique=True)
    enabled = models.BooleanField(default=False)
    value = models.IntegerField(null=True, blank=True)  # Adjust field type as per your requirement

    def __str__(self):
        return self.name

class License(models.Model):
    key = models.CharField(max_length=255, unique=True)
    validated = models.BooleanField(default=False)
    validated_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    functions = models.ManyToManyField(Function, blank=True)
    revoked = models.BooleanField(default=False)

    def is_valid(self):
        return self.validated and (self.expires_at is None or self.expires_at > timezone.now())

class Config(models.Model):
    server_url = models.URLField()
    app_instance_id = models.CharField(max_length=100, unique=True, null=True, blank=True)  # Unique identifier for the app instance
    jellyfin_api_key = models.CharField(max_length=500, unique=True,  null=False, blank=False)
class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self.create_user(email, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    jellyfin_user_id = models.CharField(max_length=255, unique=True, null=True, blank=True)  # New field

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email


class Invitation(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    invite_code = models.CharField(max_length=30, unique=True)
    max_users = models.IntegerField()
    used_count = models.IntegerField(default=0)
    expiry = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Invitation for {self.invite_code}"

    def has_space_left(self):
        return self.used_count < self.max_users

    def is_expired(self):
        if self.expiry:
            from django.utils import timezone
            return self.expiry < timezone.now()
        return False
    

class LogEntry(models.Model):
    ACTION_CHOICES = [
        ('LOGIN', 'Login'),
        ('CREATED', 'Created'),
        ('DELETED', 'Deleted'),
        ('INFO', 'Info'),
        ('WARNING', 'Warning'),
        ('ERROR', 'Error'),
        ('SETUP', 'Setup'),
        # Add more actions as needed
    ]

    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='log_entries'
    )
    message = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Log Entry'
        verbose_name_plural = 'Log Entries'

    def __str__(self):
        return f"{self.get_action_display()} - {self.user} - {self.created_at.strftime('%Y-%m-%d %H:%M:%S')}"