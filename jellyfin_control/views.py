from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponseRedirect, JsonResponse
from django.urls import reverse
from jellyfin_project import settings
from .models import Config, CustomUser, Function, Invitation, License, LogEntry
import requests
from django.contrib.auth import login
from django.http import HttpResponseBadRequest
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from datetime import datetime
from jellyfin_control.forms import LicenseForm
from django.utils import timezone
from django.contrib.auth import logout as django_logout
from django.core.paginator import Paginator
import json
from django.views.decorators.http import require_POST
from .decorators import superuser_required

def is_user_limit_exceeded():
    # Check if there is a function named "unlimited users" enabled
    unlimited_users_function = Function.objects.filter(name='unlimited users', enabled=True).exists()

    # Check if there is a function named "user limit" and get its value
    user_limit_function = Function.objects.filter(name='user limit', enabled=True).first()

    if unlimited_users_function:
        return False  # Unlimited users function found and enabled
    elif user_limit_function:
        # Example logic to check user limit based on the user limit function value
        user_limit_value = int(user_limit_function.value)  # Assuming value is stored as an integer
        active_user_count = 100  # Replace with actual logic to count active users
        return active_user_count >= user_limit_value
    else:
        return False  # Default to False if no user limit function found


def log_action(action, message, user=None):
    """Log an action using the LogEntry model."""
    LogEntry.objects.create(
        action=action,
        user=user,
        message=message
    )

def setup(request):
    if request.method == 'POST':
        
        step = request.POST.get('step')
        user = request.user if request.user.is_authenticated else None

        # Step 1: Save Server URL
        if step == '1':
            server_url = request.POST.get('server_url')
            if not server_url:
                log_action('ERROR', 'Server URL is required.', user)
                messages.error(request,"Server URL is required.")
            request.session['server_url'] = server_url
            log_action('SETUP', 'Server URL saved.', user)
            return JsonResponse({'success': True, 'step': '2'})

        # Step 2: Authenticate Admin
        elif step == '2':
            server_url = request.session.get('server_url')
            username = request.POST.get('username')
            password = request.POST.get('password')
            
            if not server_url or not username or not password:
                log_action('ERROR', 'Server URL, username, and password are required.', user)
                messages.error(request,"Server URL, username, and password are required.")
                return redirect("setup")
            try:
                token = authenticate_admin(request, server_url, username, password)
                if token:
                    request.session['token'] = token
                    log_action('SETUP', 'Admin authenticated successfully.', user)
                    return JsonResponse({'success': True, 'step': '3'})
                else:
                    log_action('ERROR', 'Authentication failed.', user)
                    return JsonResponse({'success': False, 'error': "Authentication failed."})
            except Exception as e:
                log_action('ERROR', f'Authentication failed: {str(e)}', user)
                return JsonResponse({'success': False, 'error': str(e)})

        # Step 3: Sync Users
        elif step == '3':
            server_url = request.session.get('server_url')
            token = request.session.get('token')
            
            if not server_url or not token:
                log_action('ERROR', 'Server URL and token are required.', user)
                messages.error(request,"Server URL and token are required.")
                return redirect("setup")
            try:
                sync_users(server_url, token)
                
                # Save the server URL in Config model
                config, created = Config.objects.get_or_create(id=1)
                config.server_url = server_url
                config.save()

                log_action('SETUP', 'Users synced successfully.', user)

                # Proceed to step 4 (get/generate API key)
                return JsonResponse({'success': True, 'step': '4'})
            except Exception as e:
                log_action('ERROR', f'Failed to sync users: {str(e)}', user)
                return JsonResponse({'success': False, 'error': str(e)})

        # Step 4: Generate and Retrieve API Key
        elif step == '4':
            server_url = request.session.get('server_url')
            token = request.session.get('token')

            if not server_url or not token:
                log_action('ERROR', 'Server URL and token are required.', user)
                return HttpResponseBadRequest("Server URL and token are required.")

            try:
                # Step 1: Make POST request to generate API key
                create_key_url = f"{server_url}/Auth/Keys?app=JellyfinControlApp"
                headers = {
                    'X-Emby-Token': token,
                    'Content-Type': 'application/json'
                }
                create_response = requests.post(create_key_url, headers=headers)

                if create_response.status_code == 204:
                    # Step 2: Make GET request to retrieve the newly generated API key
                    get_keys_url = f"{server_url}/Auth/Keys"
                    get_response = requests.get(get_keys_url, headers=headers)

                    if get_response.status_code == 200:
                
                        api_keys = get_response.json().get('Items', [])
                        if api_keys and len(api_keys) > 0:
                            # Save the API key in the Config model
                            api_key = api_keys[-1]['AccessToken']  # Assume the latest one is the new key
                            config, created = Config.objects.get_or_create(id=1)
                            config.jellyfin_api_key = api_key
                            config.save()

                            log_action('INFO', 'API key created and saved.', user)
                            messages.success(request, "Set up succsessful you can now login! ")
                            return redirect("login")
                        else:
                            log_action('ERROR', 'No API key found after creation.', user)
                            return JsonResponse({'success': False, 'error': "No API key found after creation."})
                    else:
                        log_action('ERROR', f'Failed to retrieve API keys: {get_response.status_code}', user)
                        return JsonResponse({'success': False, 'error': f"Failed to retrieve API keys: {get_response.status_code}"})
                else:
                    log_action('ERROR', f'Failed to create API key: {create_response.status_code}', user)
                    return JsonResponse({'success': False, 'error': f"Failed to create API key: {create_response.status_code}"})
            except Exception as e:
                log_action('ERROR', f'Error in API key creation process: {str(e)}', user)
                return JsonResponse({'success': False, 'error': str(e)})

    return render(request, 'control/setup.html')

@require_POST
def generate_api_key_view(request):
    user = request.user
    config = Config.objects.first()
    server_url = config.server_url
    access_token = request.session.get('jellyfin_access_token')
    try:
        # Step 1: Make POST request to generate API key
        create_key_url = f"{server_url}/Auth/Keys?app=JellyfinControlApp"
        headers = {
            'X-Emby-Token': access_token,
            'Content-Type': 'application/json'
        }
        create_response = requests.post(create_key_url, headers=headers)

        if create_response.status_code == 204:
            # Step 2: Make GET request to retrieve the newly generated API key
            get_keys_url = f"{server_url}/Auth/Keys"
            get_response = requests.get(get_keys_url, headers=headers)

            if get_response.status_code == 200:
                api_keys = get_response.json().get('Items', [])
                if api_keys and len(api_keys) > 0:
                    # Save the API key in the Config model
                    api_key = api_keys[-1]['AccessToken']  # Assume the latest one is the new key
                    config, created = Config.objects.get_or_create(id=1)
                    config.jellyfin_api_key = api_key
                    config.save()

                    log_action('INFO', 'API key created and saved.', user)

                    # Redirect to success page or return success response
                    return JsonResponse({'success': True, 'message': 'API key created successfully.'})
                else:
                    log_action('ERROR', 'No API key found after creation.', user)
                    return JsonResponse({'success': False, 'error': "No API key found after creation."})
            else:
                log_action('ERROR', f'Failed to retrieve API keys: {get_response.status_code}', user)
                return JsonResponse({'success': False, 'error': f"Failed to retrieve API keys: {get_response.status_code}"})
        else:
            log_action('ERROR', f'Failed to create API key: {create_response.status_code}', user)
            return JsonResponse({'success': False, 'error': f"Failed to create API key: {create_response.status_code}"})
    except Exception as e:
        log_action('ERROR', f'Error in API key creation process: {str(e)}', user)
        return JsonResponse({'success': False, 'error': str(e)})

def authenticate_admin(request, server_url, username, password):
    login_url = f"{server_url}/Users/AuthenticateByName"
    payload = {
        "Username": username,
        "Pw": password
    }

    headers = {
        'Content-Type': 'application/json',
        'X-Emby-Authorization': 'MediaBrowser Client="Other", Device="Python script", DeviceId="12345", Version="1.0.0"',
    }

    try:
        response = requests.post(login_url, json=payload, headers=headers)
        response.raise_for_status()  # Raise an exception for HTTP errors (4xx or 5xx)

        data = response.json()
        access_token = data.get('AccessToken')
        is_admin = data.get('User', {}).get('Policy', {}).get('IsAdministrator', False)

        if is_admin:
            messages.success(request, "Authentication successful. User is an administrator.")
            
            # Fetch or create the user in the Django database
     


            return access_token
        else:
            messages.error(request, "Authentication successful but user is not an administrator.")
            return None
    except requests.RequestException as e:
        messages.error(request, f"Authentication failed: {str(e)}")
        return None

def sync_users(server_url, token):
    users_url = f"{server_url}/Users"
    headers = {
        "X-Emby-Token": token
    }
    
    # Fetch the users from the server
    response = requests.get(users_url, headers=headers)
    
    if response.status_code == 200:
        users = response.json()
        
        for user in users:
            jellyfin_user_id = user.get('Id')
            email = user.get('Name')
            is_admin = user.get('Policy', {}).get('IsAdministrator', False)
            
            # Retrieve or create the user
            db_user, created = CustomUser.objects.get_or_create(jellyfin_user_id=jellyfin_user_id)
            
            if created:
                # If the user was created, set additional fields
                db_user.email = email
                db_user.is_superuser = is_admin  # Set superuser status based on admin flag
                db_user.is_staff = is_admin  # Usually, a superuser is also staff
                db_user.save()
            else:
                # If the user already exists, update their email and admin status
                db_user.email = email
                if is_admin != db_user.is_superuser:
                    db_user.is_superuser = is_admin
                    db_user.is_staff = is_admin  # Usually, a superuser is also staff
                    db_user.save()
    else:
        raise Exception(f"Failed to retrieve users: {response.status_code} - {response.text}")

def setup_success(request):
    return render(request, 'control/success.html')



def authenticate_with_jellyfin(email, password, ):
    config = Config.objects.first()
    # Perform authentication with Jellyfin here
    # Example: Assuming Jellyfin API authentication endpoint
    login_url = f"{config.server_url}/Users/AuthenticateByName"
    payload = {
        "Username": email,
        "Pw": password
    }
# Adding headers
    headers = {
        'Content-Type': 'application/json',
        'X-Emby-Authorization': 'MediaBrowser Client="Jellyfin-Control", Device="Jellyfin-Control", DeviceId="12345", Version="1.0.0"',
    }

    response = requests.post(login_url, json=payload, headers=headers)
    if response.status_code == 200:
        return True, response.json().get('AccessToken')
    else:
        return False, None

def check_and_update_superuser(request, email, access_token):
    """Check if the user is an administrator and update superuser status in Django."""
    # Retrieve server URL from Config model
    config = Config.objects.first()
    if not config:
        messages.error(request, "Configuration not found.")
        return

    server_url = config.server_url
    user_id = CustomUser.objects.filter(email=email).first().jellyfin_user_id

    user_policy_url = f"{server_url}Users/{user_id}/Policy"
    headers = {
        "X-Emby-Token": access_token
    }
    response = requests.post(user_policy_url, headers=headers)
    if response.status_code == 200:
        policy_data = response.json()
        is_admin = policy_data.get('IsAdministrator', False)
        
        # Update the user's superuser status
        db_user, _ = CustomUser.objects.get_or_create(email=email)
        if is_admin:
            db_user.is_superuser = True
            db_user.is_staff = True  # Superusers are usually staff
        else:
            db_user.is_superuser = False
            db_user.is_staff = False
        db_user.save()
    else:
        messages.error(request, f"Failed to check user admin status: {response.status_code} - {response.text}")

def custom_login(request):
    config = Config.objects.first()
    if not config:
        return redirect("setup")
    if request.user.is_authenticated:
        return redirect("home")
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        if email and password:
            # Try to authenticate with Jellyfin
            auth_success, access_token = authenticate_with_jellyfin(email, password)

            if auth_success:
                # Get or create the user
                try:
                    user, created = CustomUser.objects.get_or_create(email=email)

                    # Update the user's password
                    user.set_password(password)  # This hashes the password before saving it.
                    user.save()

                    # Log the user in
                    login(request, user)

                    # Save access token in session
                    request.session['jellyfin_access_token'] = access_token
                    server_url = config.server_url
                    token = request.session['jellyfin_access_token']
                    
                    # Sync users and update superuser status
                    sync_users(server_url, token)

                    messages.success(request, 'Signed in successfully')
                    LogEntry.objects.create(
                        action='LOGIN',
                        user=request.user,
                        message='User logged in successfully.'
                    )
                    return redirect('home')
                except CustomUser.DoesNotExist:
                    messages.error(request, "User not found in the local database.")
            else:
                # Display error message for incorrect credentials
                messages.error(request, 'Incorrect username or password')

        else:
            # If email or password is missing in POST data
            return HttpResponseBadRequest("Email and password are required fields")

    # If GET request or initial form rendering
    return render(request, 'login.html')


def custom_logout(request):
    # Clear session variables related to authentication
    if 'jellyfin_access_token' in request.session:
        del request.session['jellyfin_access_token']
    
    # Ensure the user is logged out of Django's session
    django_logout(request)
    
    # Redirect to the login page or home page
    return redirect('login')  # Adjust 'login' to your actual login page name



@login_required
def home(request):
    config = Config.objects.first()
    if config.server_url == None:
        messages.error(request, "Configuration error: No Jellyfin server URL configured.")
        return redirect('/setup')

    server_url = config.server_url
    access_token = request.session.get('jellyfin_access_token')

    # Default values if API calls fail
    server_status = "Unknown"
    server_version = "Unknown"
    total_users = "Unknown"
    active_sessions = "Unknown"
    total_movies = "Unknown"
    total_series = "Unknown"
    latest_movies = []
    latest_shows = []

    headers = {
        'X-Emby-Token': access_token,
        'Content-Type': 'application/json',
    }

    # Helper function to log errors
    def log_error(action, message):
        LogEntry.objects.create(
            action=action,
            user=request.user,
            message=message,
            created_at=timezone.now()
        )

    # Fetch server information
    try:
        server_info_response = requests.get(f'{server_url}/System/Info', headers=headers)
        server_info_response.raise_for_status()
        server_info = server_info_response.json()
        server_status = "Online"
        server_version = server_info.get('Version', 'Unknown')
    except requests.exceptions.RequestException as e:
        server_status = "Offline"
        log_error('ERROR', f"Server Info Error: {str(e)}")

    # Fetch user statistics
    try:
        users_response = requests.get(f'{server_url}/Users', headers=headers)
        users_response.raise_for_status()
        users = users_response.json()
        total_users = len(users)
    except requests.exceptions.RequestException as e:
        total_users = "Unknown"
        log_error('ERROR', f"User Statistics Error: {str(e)}")

    # Fetch active sessions
    try:
        sessions_response = requests.get(f'{server_url}/Sessions', headers=headers)
        sessions_response.raise_for_status()
        sessions = sessions_response.json()
        active_sessions = len(sessions)
    except requests.exceptions.RequestException as e:
        active_sessions = "Unknown"
        log_error('ERROR', f"Active Sessions Error: {str(e)}")

    # Fetch total movie count
    try:
        movies_response = requests.get(f'{server_url}/Items?IncludeItemTypes=Movie&Recursive=true&Fields=ItemCounts', headers=headers)
        movies_response.raise_for_status()
        movies = movies_response.json()
        total_movies = movies.get('TotalRecordCount', 'Unknown')
    except requests.exceptions.RequestException as e:
        total_movies = "Unknown"
        log_error('ERROR', f"Total Movies Error: {str(e)}")

    # Fetch total TV series count
    try:
        series_response = requests.get(f'{server_url}/Items?IncludeItemTypes=Series&Recursive=true&Fields=ItemCounts', headers=headers)
        series_response.raise_for_status()
        series = series_response.json()
        total_series = series.get('TotalRecordCount', 'Unknown')
    except requests.exceptions.RequestException as e:
        total_series = "Unknown"
        log_error('ERROR', f"Total Series Error: {str(e)}")

    # Fetch latest movies and series
    try:
        latest_movies_response = requests.get(f'{server_url}/Items/Latest', headers=headers)
        latest_movies_response.raise_for_status()
        latest_movies_data = latest_movies_response.json()

        # Check the type of the response and process accordingly
        if isinstance(latest_movies_data, dict):
            items = latest_movies_data.get('Items', [])
        elif isinstance(latest_movies_data, list):
            items = latest_movies_data
        else:
            log_error('WARNING', 'Unexpected format for latest media response.')
            items = []

        # Filter for movies only and limit to 4
        latest_movies = [item for item in items if item.get('Type') == 'Movie'][:4]
        # Filter for series only and limit to 4
        latest_shows = [item for item in items if item.get('Type') == 'Series'][:4]

    except requests.exceptions.RequestException as e:
        latest_movies = []
        latest_shows = []
        log_error('ERROR', f"Latest Media Error: {str(e)}")

    # Get recent log entries (last 4 entries)
    recent_log_entries = LogEntry.objects.order_by('-created_at')[:4]

    # Render the template with the context
    context = {
        'server_status': server_status,
        'server_version': server_version,
        'total_users': total_users,
        'active_sessions': active_sessions,
        'total_movies': total_movies,
        'total_series': total_series,
        'latest_movies': latest_movies,
        'latest_shows': latest_shows,
        'recent_log_entries': recent_log_entries,
        'config': config
    }
    
    return render(request, 'home.html', context)


@login_required
@superuser_required
def view_users(request):
    access_token = request.session.get('jellyfin_access_token')
    if not access_token:
        messages.error(request,"No access token found in session. Please log in first.")
        return redirect("logout")

    config = Config.objects.first()
    if not config:
        messages.error(request,"Configuration error: No Jellyfin server URL configured.")
        return redirect("logout")
    server_url = config.server_url
    users_url = f'{server_url}/Users'
    headers = {
        'X-Emby-Token': access_token
    }

    try:
        response = requests.get(users_url, headers=headers)
        if response.status_code == 200:
            users = response.json()
            context = {
                'users': users,
            }
            return render(request, 'control/view_users.html', context)
        else:
            error_message = f"Failed to fetch users: {response.status_code} - {response.text}"
            return render(request, 'control/view_users.html', {'error_message': error_message})
    except requests.RequestException as e:

        error_message = f"Failed to connect to Jellyfin server: {str(e)}"
        LogEntry.objects.create(
                action='ERROR',
                user=request.user,
                message=error_message
        )
        return render(request, 'control/view_users.html', {'error_message': error_message})
    


@login_required
@superuser_required
def update_user(request, user_id):
    access_token = request.session.get('jellyfin_access_token')
    if not access_token:
        return HttpResponseBadRequest("No access token found in session. Please log in first.")

    config = Config.objects.first()
    if not config:
        return HttpResponseBadRequest("Configuration error: No Jellyfin server URL configured.")

    server_url = config.server_url
    update_user_url = f'{server_url}/Users/{user_id}'  # Endpoint for updating general user data
    update_policy_url = f'{server_url}/Users/{user_id}/Policy'  # Endpoint for updating user policy data

    headers = {
        'X-Emby-Token': access_token,
        'Content-Type': 'application/json',
    }

    if request.method == 'GET':
        try:
            # Fetch current user data from Jellyfin to pre-fill the update form
            response = requests.get(update_user_url, headers=headers)
            if response.status_code == 200:
                user_data = response.json()
                context = {
                    'user_data': user_data,
                }
                return render(request, 'update_user.html', context)
            else:
                error_message = f"Failed to fetch user data: {response.status_code} - {response.text}"
                return HttpResponseBadRequest(error_message)
        except requests.RequestException as e:
            error_message = f"Failed to connect to Jellyfin server: {str(e)}"
            return HttpResponseBadRequest(error_message)

    elif request.method == 'POST':
        try:
            # Construct the updated user model based on the form input values
            updated_user_data = {
                'Name': request.POST.get('name'),
                'ServerId': request.POST.get('server_id'),
                'ServerName': request.POST.get('server_name'),
                'LastLoginDate': request.POST.get('last_login_date'),
                'LastActivityDate': request.POST.get('last_activity_date'),
                'Policy': {
                'IsAdministrator': bool(request.POST.get('is_administrator', False)),
                'EnableCollectionManagement': bool(request.POST.get('enable_collection_management', False)),
                'EnableSubtitleManagement': bool(request.POST.get('enable_subtitle_management', False)),
                'EnableLyricManagement': bool(request.POST.get('enable_lyric_management', False)),
                'IsDisabled': bool(request.POST.get('is_disabled', False)),
                'EnableUserPreferenceAccess': bool(request.POST.get('enable_user_preference_access', False)),
                'EnableRemoteControlOfOtherUsers': bool(request.POST.get('enable_remote_control_of_other_users', False)),
                'EnableSharedDeviceControl': bool(request.POST.get('enable_shared_device_control', False)),
                'EnableRemoteAccess': bool(request.POST.get('enable_remote_access', False)),
                'EnablePlaybackRemuxing': bool(request.POST.get('enable_playback_remuxing', False)),
                'ForceRemoteSourceTranscoding': bool(request.POST.get('force_remote_source_transcoding', False)),
                'PasswordResetProviderId': request.POST.get('password_reset_provider_id', 'default_provider_id'),
                'AuthenticationProviderId': request.POST.get('authentication_provider_id', 'default_auth_provider_id'),
                }
            }

            # Update general user data
            response = requests.post(update_user_url, json=updated_user_data, headers=headers)
            if response.status_code != 204:
                error_message = f"Failed to update user data: {response.status_code} - {response.text}"
                return render(request, 'update_user.html', {'error_message': error_message})

            # Construct the updated policy based on the form input values
            updated_policy_data = {
                'IsAdministrator': bool(request.POST.get('is_administrator', False)),
                'EnableCollectionManagement': bool(request.POST.get('enable_collection_management', False)),
                'EnableSubtitleManagement': bool(request.POST.get('enable_subtitle_management', False)),
                'EnableLyricManagement': bool(request.POST.get('enable_lyric_management', False)),
                'IsDisabled': bool(request.POST.get('is_disabled', False)),
                'EnableUserPreferenceAccess': bool(request.POST.get('enable_user_preference_access', False)),
                'EnableRemoteControlOfOtherUsers': bool(request.POST.get('enable_remote_control_of_other_users', False)),
                'EnableSharedDeviceControl': bool(request.POST.get('enable_shared_device_control', False)),
                'EnableRemoteAccess': bool(request.POST.get('enable_remote_access', False)),
                'EnablePlaybackRemuxing': bool(request.POST.get('enable_playback_remuxing', False)),
                'ForceRemoteSourceTranscoding': bool(request.POST.get('force_remote_source_transcoding', False)),
                'PasswordResetProviderId': request.POST.get('password_reset_provider_id', 'default_provider_id'),
                'AuthenticationProviderId': request.POST.get('authentication_provider_id', 'default_auth_provider_id'),
            }

            # Update user policy data
            response = requests.post(update_policy_url, json=updated_policy_data, headers=headers)
            if response.status_code != 204:
                error_message = f"Failed to update user policy: {response.status_code} - {response.text}"
                return render(request, 'update_user.html', {'error_message': error_message})

            # Handle successful update, redirect or render success message
            messages.success(request, "User Updated")
            return redirect('view_users')  # Redirect to view users page or success page

        except requests.RequestException as e:
            error_message = f"Failed to connect to Jellyfin server: {str(e)}"
            return render(request, 'update_user.html', {'error_message': error_message})

    return HttpResponseBadRequest("Invalid request method")




@login_required
@superuser_required
def create_user(request):
    access_token = request.session.get('jellyfin_access_token')
    if not access_token:
        messages.error(request, "No access token found in session. Please log in first.")
        return redirect('login')  # Adjust to your login URL

    config = Config.objects.first()
    if not config:
        messages.error(request, "Configuration error: No Jellyfin server URL configured.")
        return redirect('settings')  # Adjust to your settings URL

    server_url = config.server_url
    create_user_url = f'{server_url}/Users/New'

    headers = {
        'X-Emby-Token': access_token,
        'Content-Type': 'application/json',
    }

    if request.method == 'POST':
        try:
            # Check user limit based on function settings (optional)
            # if is_user_limit_exceeded():
            #     messages.error(request, 'User creation failed. Maximum user limit reached.')
            #     return redirect('view_users')  # Redirect to user management page

            # Construct the new user data based on the form input values
            new_user_data = {
                'Name': request.POST.get('name'),
                'Password': request.POST.get('password'),
                # Add other required fields as per your Jellyfin API documentation
            }

            # Send a POST request to create a new user
            response = requests.post(create_user_url, json=new_user_data, headers=headers)

            if response.status_code == 200:
                # Handle successful creation
                messages.success(request, "User created successfully.")
                LogEntry.objects.create(
                    action='CREATED',
                    user=request.user,
                    message=f"User '{new_user_data['Name']}' created successfully."
                )
                token = access_token
                sync_users(server_url, token)
                return redirect('view_users')  # Redirect to user management page
            else:
                # Handle failed creation
                messages.error(request, f"Failed to create user: {response.status_code} - {response.text}")
                LogEntry.objects.create(
                    action='ERROR',
                    user=request.user,
                    message=f"Failed to create user '{new_user_data['Name']}': {response.status_code} - {response.text}"
                )
                return redirect('view_users')  # Redirect back to user management with an error message

        except requests.RequestException as e:
            # Handle connection errors
            error_message = f"Failed to connect to Jellyfin server: {str(e)}"
            messages.error(request, error_message)
            LogEntry.objects.create(
                action='ERROR',
                user=request.user,
                message=error_message
            )
            return redirect('view_users')  # Redirect back to user management with an error message

    return HttpResponseBadRequest("Invalid request method")

@login_required
@superuser_required
def delete_user(request, user_id):
    access_token = request.session.get('jellyfin_access_token')
    if not access_token:
        return HttpResponseBadRequest("No access token found in session. Please log in first.")

    config = Config.objects.first()  # Retrieve your configuration model
    if not config:
        return HttpResponseBadRequest("Configuration error: No Jellyfin server URL configured.")

    server_url = config.server_url
    delete_user_url = f'{server_url}/Users/{user_id}'
    get_user_url = f'{server_url}/Users/{user_id}'

    headers = {
        'X-Emby-Token': access_token,
    }

    if request.method == 'POST':
        try:
            # Fetch the user details first to get the username
            user_response = requests.get(get_user_url, headers=headers)
            if user_response.status_code == 200:
                user_data = user_response.json()
                username = user_data.get('Name')

                # Send DELETE request to Jellyfin API to delete the user
                response = requests.delete(delete_user_url, headers=headers)
                if response.status_code == 204:
                    # Delete the user from Django database
                    try:
                        django_user = CustomUser.objects.get(jellyfin_user_id=user_id)
                        django_user.delete()
                        messages.success(request, f"User '{username}' successfully deleted from Jellyfin and Django.")
                        LogEntry.objects.create(
                            action='DELETED',
                            user=request.user,
                            message=f"User '{username}' deleted successfully from Jellyfin and Django."
                        )
                    except CustomUser.DoesNotExist:
                        messages.warning(request, f"User '{username}' was not found in the Django database.")
                        LogEntry.objects.create(
                            action='DELETED',
                            user=request.user,
                            message=f"Attempted to delete user '{username}' from Jellyfin. User was not found in the Django database."
                        )
                    token = access_token
                    sync_users(server_url, token)
                    return redirect('view_users')  # Redirect to view users page or success page
                else:
                    error_message = f"Failed to delete user '{username}' from Jellyfin: {response.status_code} - {response.text}"
                    return HttpResponseBadRequest(error_message)
            else:
                error_message = f"Failed to fetch user details: {user_response.status_code} - {user_response.text}"
                return HttpResponseBadRequest(error_message)

        except requests.RequestException as e:
            error_message = f"Failed to connect to Jellyfin server: {str(e)}"
            return HttpResponseBadRequest(error_message)

    return HttpResponseBadRequest("Invalid request method")



@login_required
def invitation_list(request):
    user = request.user
    if user.is_superuser:
        invitations = Invitation.objects.all()
    else:
        invitations = Invitation.objects.filter(user=user)
    
    return render(request, 'invitation_list.html', {'invitations': invitations})

@login_required
def invitation_create(request):
    if request.method == 'POST':
        invite_code = request.POST.get('invite_code')
        max_users = request.POST.get('max_users')
        expiry_str = request.POST.get('expiry')

        # Validate inputs
        if not invite_code or not max_users:
            messages.error(request, "Invite code and max users are required.")
            LogEntry.objects.create(
                action='ERROR',
                user=request.user,
                message="Failed to create invitation: Invite code and max users are required."
            )
            return redirect('invitation_create')

        try:
            max_users = int(max_users)
        except ValueError:
            messages.error(request, "Max users must be a valid integer.")
            LogEntry.objects.create(
                action='ERROR',
                user=request.user,
                message="Failed to create invitation: Max users is not a valid integer."
            )
            return redirect('invitation_create')

        if expiry_str:
            try:
                # Ensure the correct datetime format for Django
                expiry = datetime.strptime(expiry_str, '%Y-%m-%dT%H:%M')
            except ValueError:
                messages.error(request, "Invalid date format for expiry. Use YYYY-MM-DDTHH:MM format.")
                LogEntry.objects.create(
                    action='ERROR',
                    user=request.user,
                    message="Failed to create invitation: Invalid date format for expiry."
                )
                return redirect('invitation_create')
        else:
            expiry = None

        # Create invitation
        try:
            user = request.user
            invitation = Invitation(invite_code=invite_code, max_users=max_users, expiry=expiry, user=user)
            invitation.save()
            messages.success(request, "Invitation created successfully.")
            LogEntry.objects.create(
                action='CREATED',
                user=request.user,
                message=f"Invitation '{invite_code}' created successfully with max users {max_users} and expiry {expiry}."
            )
        except Exception as e:
            messages.error(request, f"An error occurred: {e}")
            LogEntry.objects.create(
                action='ERROR',
                user=request.user,
                message=f"Failed to create invitation '{invite_code}': {str(e)}"
            )

        return redirect('invitation_list')

    return render(request, 'invitation_create.html')


@login_required
def invitation_delete(request, invitation_id):
    if request.method == 'POST':
        try:
            invitation = get_object_or_404(Invitation, pk=invitation_id)
            invite_code = invitation.invite_code  # Capture the invite code before deletion
            invitation.delete()
            messages.success(request, "Invitation deleted successfully.")
            LogEntry.objects.create(
                action='DELETED',
                user=request.user,
                message=f"Invitation '{invite_code}' deleted successfully."
            )
            return redirect('invitation_list')
        except Exception as e:
            messages.error(request, f"Failed to delete invitation: {e}")
            LogEntry.objects.create(
                action='ERROR',
                user=request.user,
                message=f"Failed to delete invitation '{invitation_id}': {str(e)}"
            )
            return redirect('invitation_list')
    else:
        messages.error(request, "Invalid request method.")
        return HttpResponseBadRequest("Invalid request method")
    
def enter_invite(request):
    config = Config.objects.first()
    if not config:
        return redirect("setup")
    if request.method == 'POST':
        invite_code = request.POST.get('invite_code')
        return redirect(f'/register/{invite_code}')
    return render(request, 'enter_invite.html')


def register(request, invite_code):
    config = Config.objects.first()
    if not config:
        return redirect("setup")
    try:
        invitation = Invitation.objects.get(invite_code=invite_code)
    except Invitation.DoesNotExist:
        messages.error(request, "Invalid invitation code.")
        return redirect('enter_invite')  # Redirect to the enter_invite page without invite_code

    if not invitation.has_space_left():
        messages.error(request, "No spaces left for this invitation code.")
        return redirect('enter_invite')

    if invitation.is_expired():
        messages.error(request, "Invitation code has expired.")
        return redirect('enter_invite')

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        email = request.POST.get('email')

        # Check if the username (email) is already taken in Jellyfin
        access_token = config.jellyfin_api_key
        server_url = config.server_url
        user_check_url = f"{server_url}/Users/{username}"
        headers = {
            'X-Emby-Token': access_token,
            'Content-Type': 'application/json',
        }

        try:
            response = requests.get(user_check_url, headers=headers)
            if response.status_code == 200:
                messages.error(request, "Username is already taken.")
                return redirect('enter_invite')
        except requests.exceptions.RequestException as e:
            messages.error(request, f"Failed to check username: {str(e)}")
            return redirect('enter_invite')

        # Check if passwords match
        if password != password2:
            messages.error(request, "Passwords do not match.")
            return redirect('enter_invite')

        # Create Jellyfin user via API
        jellyfin_user_data = {
            'Name': username,
            'Password': password,
            'EnableAutoLogin': True  # Adjust as per your Jellyfin API requirements
        }

        try:
            response = requests.post(f'{server_url}/Users/New', json=jellyfin_user_data, headers=headers)
            response.raise_for_status()
            jellyfin_user_id = response.json().get('Id')
        except requests.exceptions.RequestException as e:
            messages.error(request, f"Failed to create Jellyfin user: {str(e)}")
            return redirect('enter_invite')

        # Create the user in Django database using CustomUserManager
        try:
            user = CustomUser.objects.create_user(email=email, password=password, jellyfin_user_id=jellyfin_user_id)
            messages.success(request, "Registration successful. You can now log in.")
            
            # Log the user creation
            log_message = (f"User created: {email} using invitation code: {invite_code}. "
                           f"Invitation created by: {invitation.user.email if invitation.user else 'Unknown'}")
            LogEntry.objects.create(
                action='CREATED',
                user=invitation.user,
                message=log_message
            )
        except ValueError as e:
            messages.error(request, str(e))
            return redirect('enter_invite')

        # Update the invitation used count
        invitation.used_count += 1
        invitation.save()

        return redirect('registration_success')

    return render(request, 'registration/register.html', {'invite_code': invite_code})


def registration_success(request):
    config = Config.objects.first()
    server_url = config.server_url
    return render(request, 'registration_success.html', {'server_url': server_url})


@login_required
@superuser_required
def enter_license_key(request):
    try:
        license = License.objects.get(id=1)  # Assuming a single license per installation
    except License.DoesNotExist:
        license = None

    config = Config.objects.first()
    device_id = config.app_instance_id

    if request.method == 'POST':
        form = LicenseForm(request.POST)
        if form.is_valid():
            key = form.cleaned_data['key']
            response = requests.get(f"{settings.LICENSING_SERVER_URL}/api/validate/", params={'key': key})

            if response.status_code == 200:
                try:
                    data = response.json()
                    app_name = data.get('app_name')
                    license_device_id = data.get('app_instance_id')
                    functions = data.get('functions', [])
                    first_time_use = data.get('first_time_use')  # Default to False if not provided

                    if data.get('valid'):
                        if app_name != settings.APP_NAME:
                            form.add_error('key', 'Incorrect application name for this license key.')
                        elif license_device_id != device_id:
                            if not config.app_instance_id:  # Check if app_instance_id is not already set
                                if first_time_use:
                                    config.app_instance_id = license_device_id
                                    config.save()
                                    messages.info(request, 'Application Instance ID set successfully.')
                                # Proceed to validate license key and update functions
                                else:
                                    form.add_error('key', 'This license key has already been activated on another system.')

                            else:
                                form.add_error('key', 'This license key has already been activated on another system.')
                                return render(request, 'enter_license_key.html', {'form': form, 'license': license, 'config': config})
                        else:
                            if not license:
                                license = License.objects.create(id=1, key=key)
                            else:
                                license.key = key
                                license.validated = True
                                license.validated_at = timezone.now()

                            expires_at = data.get('expires_at')
                            if expires_at:
                                license.expires_at = timezone.datetime.fromisoformat(expires_at)
                                license.save()

                                # Update functions
                                existing_functions = {func.name: func for func in Function.objects.all()}
                                for function_data in functions:
                                    function_name = function_data.get('name')
                                    function_enabled = function_data.get('enabled', False)
                                    if function_name in existing_functions:
                                        function = existing_functions[function_name]
                                        function.enabled = function_enabled
                                    else:
                                        function = Function(name=function_name, enabled=function_enabled)
                                        function.save()
                                        license.functions.add(function)

                                # Set app_instance_id if first_time_use
                                if first_time_use:
                                    if not config.app_instance_id:
                                        config.app_instance_id = license_device_id
                                        config.save()
                                    else:
                                        form.add_error('key', 'This license key has already been activated on another system.')
                                        return render(request, 'enter_license_key.html', {'form': form, 'license': license, 'config': config})
                                license.validated = True
                                license.save()
                                messages.success(request, 'License key successfully validated.')
                                return redirect('/home/')  # Redirect to a protected view or home page
                            else:
                                form.add_error('key', 'Invalid response from licensing server (missing expires_at)')
                    else:
                        form.add_error('key', 'Invalid or expired license key.')
                except ValueError:
                    form.add_error('key', 'Invalid JSON response from licensing server')
            else:
                form.add_error('key', f'Failed to validate license key: {response.status_code}')
        else:
            form.add_error(None, 'Form data is not valid')
    else:
        form = LicenseForm(initial={'key': license.key if license else ''})

    return render(request, 'enter_license_key.html', {'form': form, 'license': license, 'config': config})

@login_required
@superuser_required
def revalidate_license(request):
    if request.method == 'POST':
        license_key = request.POST.get('license_key')
        if license_key:
            response = requests.get(f"{settings.LICENSING_SERVER_URL}/api/validate/", params={'key': license_key})
            if response.status_code == 200:
                try:
                    data = response.json()
                    app_name = data.get('app_name')
                    license_device_id = data.get('app_instance_id')
                    functions = data.get('functions', [])

                    # Fetch the Config object and device_id
                    config = Config.objects.first()
                    device_id = config.app_instance_id if config else None

                    if data.get('valid'):
                        if app_name != settings.APP_NAME:
                            messages.error(request, 'Incorrect application name for this license key.')
                            return redirect('/enter-license-key/')  # Redirect with error message
                        elif license_device_id != device_id:
                            messages.error(request, 'Incorrect device ID for this license key.')
                            return redirect('/enter-license-key/')  # Redirect with error message
                        else:
                            try:
                                license = License.objects.get(id=1)  # Assuming a single license per installation
                                expires_at = data.get('expires_at')
                                if expires_at:
                                    license.expires_at = timezone.datetime.fromisoformat(expires_at)
                                    license.validated = True

                                    license.save()

                                    # Update functions
                                    existing_functions = {func.name: func for func in Function.objects.all()}
                                    for function in functions:
                                        function_name = function['name']
                                        function_enabled = function['enabled']
                                        if function_name in existing_functions:
                                            func = existing_functions[function_name]
                                            func.enabled = function_enabled
                                        else:
                                            func = Function(name=function_name, enabled=function_enabled)
                                        func.save()
                                        license.functions.add(func)
                                    license.revoked = False
                                    license.save()
                                    messages.success(request, 'License key successfully revalidated.')
                                    return redirect('/home/')  # Redirect to a protected view or home page
                                else:
                                    messages.error(request, 'Invalid response from licensing server (missing expires_at).')
                                    return redirect('/enter-license-key/')  # Redirect with error message
                            except License.DoesNotExist:
                                messages.error(request, 'License not found in local database.')
                                return redirect('/enter-license-key/')  # Redirect with error message
                    else:
                        messages.error(request, 'Invalid or expired license key.')
                        return redirect('/enter-license-key/')  # Redirect with error message
                except ValueError:
                    messages.error(request, 'Invalid JSON response from licensing server.')
                    return redirect('/enter-license-key/')  # Redirect with error message
            else:
                data = response.json()
                error = data.get('error')
                messages.error(request, f'Failed to validate license key: {error}.')
                return redirect('/enter-license-key/')  # Redirect with error message
        else:
            messages.error(request, 'License key missing in request.')
            return redirect('/enter-license-key/')  # Redirect with error message
    else:
        messages.error(request, 'Invalid request method.')
        return redirect('/enter-license-key/')  # Redirect with error message
    
@login_required
@superuser_required
def view_license(request):
    try:
        license = License.objects.get(id=1)
    except License.DoesNotExist:
        # Handle the case where license with id=1 does not exist
        return HttpResponseRedirect(reverse('enter_license_key'))

    config = Config.objects.first()  # Assuming you have only one instance of Config
    if not config:
        # Handle case where Config object does not exist
        app_instance_id = None
    else:
        app_instance_id = config.app_instance_id

    context = {
        'license': license,
        'app_instance_id': app_instance_id,
        'app_name': settings.APP_NAME,
    }

    return render(request, 'control/view_license.html', context)



@login_required
@superuser_required
def settings_view(request):
    if request.method == 'POST':
        # Handle Config Update
        config_instance = Config.objects.first()  # Assuming only one instance of Config
        if config_instance:
            config_instance.server_url = request.POST.get('server_url')
            config_instance.save()

        messages.success(request, 'Settings updated successfully.')
        return redirect('settings')

    else:
        # Load current settings
        config_instance = Config.objects.first()
        license_instance = License.objects.first()

        return render(request, 'settings.html', {
            'config': config_instance,
            'license': license_instance,
        })
    

@login_required
@superuser_required
def logs_view(request):
    logs = LogEntry.objects.all()
    paginator = Paginator(logs, 10)  # Show 10 logs per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'logs.html', {'page_obj': page_obj})




@login_required
def movie_list(request):
    access_token = request.session.get('jellyfin_access_token')
    if not access_token:
        return redirect('login')  # Redirect to your login view if no access token is found
    
    try:
        config = Config.objects.first()
        server_url = config.server_url
    except Config.DoesNotExist:
        return render(request, 'error.html', {'error': 'Server configuration not found.'})
    
    movies_url = f"{server_url}/Items"

    headers = {
        'X-Emby-Token': access_token,
        'Content-Type': 'application/json',
    }

    params = {
        'IncludeItemTypes': 'Movie',
        'Recursive': True,
        'Fields': 'PrimaryImageAspectRatio,ImageTags',
        'StartIndex': 0,
        'Limit': 1000,  # Large limit to fetch all movies
    }

    try:
        response = requests.get(movies_url, headers=headers, params=params)
        response.raise_for_status()
        movies_data = response.json().get('Items', [])
    except requests.exceptions.RequestException as e:
        return render(request, 'error.html', {'error': str(e)})

    paginator = Paginator(movies_data, 50)  # Paginate with 100 movies per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'movie_list.html', {
        'page_obj': page_obj,
        'config': config,
        'all_movies': json.dumps(movies_data),  # Convert to JSON string
    })


@login_required
def movie_detail(request, movie_id):
    config = Config.objects.first()
    if not config:
        messages.error(request, "Configuration error: No Jellyfin server URL configured.")
        return redirect('home')  # Redirect to home or other suitable page

    server_url = config.server_url
    access_token = request.session.get('jellyfin_access_token')
    headers = {
        'X-Emby-Token': access_token,
        'Content-Type': 'application/json',
    }
    
    movie_url = f'{server_url}/Items/{movie_id}'

    try:
        response = requests.get(movie_url, headers=headers)
        response.raise_for_status()
        movie_data = response.json()
    except requests.RequestException as e:
        messages.error(request, f"Error fetching movie details: {str(e)}")
        return redirect('home')

    return render(request, 'movie_detail.html', {'movie': movie_data, 'config': config})







@login_required
@superuser_required
def reset_user_password(request, user_id):
    # Ensure only superusers can reset passwords
    if not request.user.is_superuser:
        messages.error(request, "You do not have permission to reset passwords.")
        return redirect('dashboard')

    if request.method == 'POST':
        # Extract form data
        config = get_object_or_404(Config, pk=1)  # Assuming there's only one config entry
        new_password = request.POST.get('new_password', '')

        # Fetch the user's access token from the session
        jellyfin_token = request.session.get('jellyfin_access_token')
        
        # Define the headers including the authorization token
        headers = {
            'Authorization': f'MediaBrowser Token={jellyfin_token}',
            'Content-Type': 'application/json'
        }
        
        # Step 1: Trigger the password reset
        reset_payload = {
            'ResetPassword': True,
            'CurrentPw': None,
            'NewPw': None
        }

        reset_url = f'{config.server_url}/Users/{user_id}/Password'

        try:
            reset_response = requests.post(reset_url, json=reset_payload, headers=headers)

            if reset_response.status_code == 204:
                # Step 2: Set the new password
                password_payload = {
                    'ResetPassword': False,
                    'CurrentPw': None,  # Not needed since the password reset was triggered
                    'NewPw': new_password
                }

                password_response = requests.post(reset_url, json=password_payload, headers=headers)

                if password_response.status_code == 204:
                    messages.success(request, "Password successfully reset.")
                    return redirect('view_users')
                else:
                    messages.error(request, "Failed to set the new password.")
            else:
                messages.error(request, "Failed to initiate the password reset.")

        except requests.exceptions.RequestException as e:
            messages.error(request, f"Failed to reset password: {e}")

    # Render the password reset form
    return render(request, 'reset_password.html', {'user_id': user_id})

@login_required
@superuser_required
def view_devices(request):
    # Ensure only superusers can access this view
    if not request.user.is_superuser:
        messages.error(request, "You do not have permission to view this page.")
        return redirect('home')  # Redirect to the home page

    config = Config.objects.first()  # Assuming there's only one config entry
    url = f'{config.server_url}/Devices'

    # Fetch the user's access token from the session
    jellyfin_token = request.session.get('jellyfin_access_token')

    headers = {
        'Authorization': f'MediaBrowser Token={jellyfin_token}',
        'Content-Type': 'application/json'
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Will raise an exception for HTTP errors

        devices_data = response.json()

    except requests.exceptions.RequestException as e:
        devices_data = {'Items': [], 'TotalRecordCount': 0}
        messages.error(request, f"Failed to fetch devices: {e}")

    # Pass the devices data to the template
    return render(request, 'view_devices.html', {'devices': devices_data['Items']})


@login_required
@superuser_required
def sessions_page(request):
    if not request.user.is_superuser:
        messages.error(request, "You do not have permission to view sessions.")
        return redirect('home')

    config = Config.objects.get(pk=1)  # Assuming there's only one config entry
    url = f'{config.server_url}/Sessions'

    # Fetch the user's access token from the session
    jellyfin_token = request.session.get('jellyfin_access_token')

    # Define the headers including the authorization token
    headers = {
        'Authorization': f'MediaBrowser Token={jellyfin_token}',
        'Content-Type': 'application/json'
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        sessions = response.json()  # Directly use the response JSON which is a list
    except requests.exceptions.RequestException as e:
        messages.error(request, f"Failed to retrieve sessions: {e}")
        sessions = []

    return render(request, 'sessions_page.html', {'sessions': sessions})