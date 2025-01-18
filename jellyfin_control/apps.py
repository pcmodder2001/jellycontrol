from django.apps import AppConfig


class JellyfinControlConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'jellyfin_control'

    def ready(self):
        try:
            from . import email_config
            email_config.update_email_settings()
        except Exception as e:
            print(f"Error in app ready: {str(e)}")
