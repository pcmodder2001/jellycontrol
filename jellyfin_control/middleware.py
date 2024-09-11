# middleware.py

from django.http import HttpResponseRedirect
from django.urls import reverse
from django.utils import timezone
from .models import License, Function, Config
import requests
from django.conf import settings
from django.contrib import admin
from django.shortcuts import redirect

class LicenseKeyMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Bypass license key check for specific views and Django admin
        excluded_paths = [
            reverse('enter_license_key'),
            reverse('revalidate_license'),
            reverse('login'),
            reverse('logout'),
            reverse('admin:index'),  # Example: Django admin index
            reverse('admin:app_list', kwargs={'app_label': 'auth'}),  # Example: Django admin auth app
            reverse('view_license'),
            reverse('settings'),
            reverse('setup')
            # Add more admin URLs as needed
        ]

        if any(request.path.startswith(path) for path in excluded_paths):
            return self.get_response(request)
        
        try:
            license = License.objects.get(id=1)
        except License.DoesNotExist:
            return HttpResponseRedirect(reverse('enter_license_key'))

        if not license.is_valid():
            return HttpResponseRedirect(reverse('enter_license_key'))

        # Validate the license with the licensing server
        response = requests.get(f"{settings.LICENSING_SERVER_URL}/api/validate/", params={'key': license.key})
        
        if response.status_code != 200:
            license.revoked = True
            # Handle case where server response is not successful
            license.validated = False
            license.save()
            return HttpResponseRedirect(reverse('enter_license_key'))

        data = response.json()
        if not data.get('valid'):
            # Handle case where license key is not valid
            license.validated = False
            license.save()
            return HttpResponseRedirect(reverse('enter_license_key'))

        # Fetch the Config object and device_id
        config = Config.objects.first()
        device_id = config.app_instance_id if config else None

        if data.get('app_name') != settings.APP_NAME:
            license.validated = False
            license.save()
            return HttpResponseRedirect(reverse('enter_license_key'))

        if data.get('app_instance_id') != device_id:
            license.validated = False
            license.save()
            return HttpResponseRedirect(reverse('enter_license_key'))

        # Update the function list
        functions = data.get('functions', [])
        existing_functions = {func.name: func for func in Function.objects.all()}

        for function in functions:
            function_name = function['name']
            function_enabled = function['enabled']
            function_value = function['value']
            if function_name in existing_functions:
                func = existing_functions[function_name]
                func.enabled = function_enabled
                func.value = function_value
            else:
                func = Function(name=function_name, enabled=function_enabled, value=function_value)
            func.save()
            license.functions.add(func)

        license.save()

        expires_at_str = data.get('expires_at')
        if expires_at_str:
            # Parse expires_at string into datetime object
            try:
                expires_at = timezone.datetime.fromisoformat(expires_at_str)
            except ValueError:
                expires_at = None  # Handle invalid datetime format gracefully
            
            if expires_at and expires_at > timezone.now():
                # Update expires_at in the local database if necessary
                if license.expires_at != expires_at:
                    license.expires_at = expires_at
                    license.save()
            else:
                # Handle case where license has expired
                license.validated = False
                license.save()
                return HttpResponseRedirect(reverse('enter_license_key'))
        license.revoked = False
        return self.get_response(request)

class CheckJellyfinAccessTokenMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Check if the user is authenticated and the jellyfin_access_token is missing
        if request.user.is_authenticated and 'jellyfin_access_token' not in request.session:
            # Log the user out
            
            # Redirect to the login page or wherever appropriate
            return redirect('logout')
        
        # Proceed with the request
        response = self.get_response(request)
        return response



