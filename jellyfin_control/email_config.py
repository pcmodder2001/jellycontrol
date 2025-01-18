from django.conf import settings
from .models import EmailSettings

def update_email_settings():
    """Update email settings from database"""
    try:
        email_config = EmailSettings.objects.first()
        if email_config:
            settings.EMAIL_HOST = email_config.smtp_host
            settings.EMAIL_PORT = email_config.smtp_port
            settings.EMAIL_USE_TLS = email_config.use_tls
            settings.EMAIL_USE_SSL = email_config.use_ssl
            settings.EMAIL_HOST_USER = email_config.smtp_username
            settings.EMAIL_HOST_PASSWORD = email_config.smtp_password
            settings.DEFAULT_FROM_EMAIL = email_config.from_email
    except Exception as e:
        print(f"Error loading email settings: {str(e)}") 