from django.contrib import messages
from django.shortcuts import redirect
from functools import wraps

def superuser_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_superuser:
            # Add an error message to the message framework
            messages.error(request, "You must be a admin to access this page.")
            # Redirect to the home page
            return redirect('home')  # Replace 'home' with your actual home page URL name
        return view_func(request, *args, **kwargs)
    
    return _wrapped_view
