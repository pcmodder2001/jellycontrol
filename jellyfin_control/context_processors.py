# your_app/context_processors.py

from django.contrib.auth.models import Permission
from django.core.exceptions import ObjectDoesNotExist
from .models import Invitation, Config


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



def check_default_invite(request):
    """
    Context processor to check if the default invite exists.
    """
    default_invite_code = None
    default_invite_exists = False

    try:
        # Fetch the invite_code from the Config model
        config = Config.objects.first()  # Assuming there's only one Config object
        if config and config.invite_code:
            default_invite_code = config.invite_code
            # Check if the invitation exists
            default_invite_exists = Invitation.objects.filter(invite_code=default_invite_code).exists()
    except ObjectDoesNotExist:
        pass

    return {
        'default_invite_code': default_invite_code,
        'default_invite_exists': default_invite_exists,
    }