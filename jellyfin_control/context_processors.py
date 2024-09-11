# your_app/context_processors.py

from django.contrib.auth.models import Permission

def is_superuser(request):
    return {
        'is_superuser': request.user.is_authenticated and request.user.is_superuser
    }

def user_info(request):
    """
    Context processor to add the username of the logged-in user to the context.
    """
    if request.user.is_authenticated:
        return {'username': request.user.email}
    return {'username': None}