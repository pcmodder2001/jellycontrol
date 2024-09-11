# your_app/context_processors.py

from django.contrib.auth.models import Permission

def is_superuser(request):
    return {
        'is_superuser': request.user.is_authenticated and request.user.is_superuser
    }