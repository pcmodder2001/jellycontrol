import os
import shutil
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponseRedirect, JsonResponse
from django.urls import reverse
from jellyfin_project import settings
from .models import Config, CustomUser, Function, Invitation, License, LogEntry, EmailSettings, BlacklistedEmail
import requests
from django.contrib.auth import login
from django.http import HttpResponseBadRequest
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from datetime import datetime
from jellyfin_control.forms import  ConfigForm, EmailSettingsForm
from django.utils import timezone
from django.contrib.auth import logout as django_logout
from django.core.paginator import Paginator
import json
from django.views.decorators.http import require_POST
from .decorators import superuser_required
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core.mail import send_mail
from django.http import HttpResponse
from django.utils.http import urlsafe_base64_decode
from packaging import version  # To handle version comparison
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from django.http import FileResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.management import call_command
import re
import random
import string
from django.db import IntegrityError




def log_action(action, message, user=None):
    """Log an action using the LogEntry model."""
    try:
        # Only create log entry if we have a user or if user is optional
        if user is not None:
            LogEntry.objects.create(
                action=action,
                user=user,
                message=message
            )
        else:
            # Create log entry without user reference
            LogEntry.objects.create(
                action=action,
                message=message
            )
    except Exception as e:
        # Silently handle logging errors to prevent disrupting main flow
        print(f"Logging error: {str(e)}")
    
@require_POST
def generate_api_key_view(request):
    try:
        if not request.user.is_authenticated:
            return JsonResponse({
                'success': False,
                'error': 'User must be authenticated'
            }, status=401)

        config = Config.objects.first()
        server_url = config.server_url
        access_token = request.session.get('jellyfin_access_token')

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
                    api_key = api_keys[-1]['AccessToken']
                    config.jellyfin_api_key = api_key
                    config.save()

                    # Log the action only if user is authenticated
                    if isinstance(request.user, CustomUser):
                        log_action('INFO', 'API key created and saved.', request.user)

                    messages.success(request, "API key created successfully")
                    return JsonResponse({'success': True, 'message': 'API key created successfully.'})
                else:
                    return JsonResponse({'success': False, 'error': "No API key found after creation."})
            else:
                return JsonResponse({'success': False, 'error': f"Failed to retrieve API keys: {get_response.status_code}"})
        else:
            return JsonResponse({'success': False, 'error': f"Failed to create API key: {create_response.status_code}"})

    except Exception as e:
        # Log error without user if there's an exception
        log_action('ERROR', f'Error in API key creation process: {str(e)}')
        return JsonResponse({'success': False, 'error': str(e)})
    
    
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
                return JsonResponse({
                    'success': False, 
                    'error': 'Server URL and token are required.'
                })

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
                            api_key = api_keys[-1]['AccessToken']
                            config, created = Config.objects.get_or_create(id=1)
                            config.jellyfin_api_key = api_key
                            config.save()

                            log_action('INFO', 'API key created and saved.', user)
                            
                            # Return JSON response for AJAX
                            return JsonResponse({
                                'success': True,
                                'message': 'Setup completed successfully',
                                'redirect_url': reverse('login')
                            })
                        else:
                            return JsonResponse({
                                'success': False,
                                'error': "No API key found after creation."
                            })
                    else:
                        return JsonResponse({
                            'success': False,
                            'error': f"Failed to retrieve API keys: {get_response.status_code}"
                        })
                else:
                    return JsonResponse({
                        'success': False,
                        'error': f"Failed to create API key: {create_response.status_code}"
                    })

            except Exception as e:
                log_action('ERROR', f'Error in API key creation process: {str(e)}', user)
                return JsonResponse({
                    'success': False,
                    'error': str(e)
                })

    return render(request, 'control/setup.html')



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
           
            
            # Fetch or create the user in the Django database
     


            return access_token
        else:
            messages.error(request, "Authentication successful but user is not an administrator.")
            return None
    except requests.RequestException as e:
        messages.error(request, f"Authentication failed: {str(e)}")
        return None

def sync_users(server_url, token):
    """Sync users from Jellyfin to Django database."""
    print("Starting sync_users function...")
    users_url = f"{server_url}/Users"
    headers = {
        "X-Emby-Token": token
    }
    
    try:
        response = requests.get(users_url, headers=headers)
        if response.status_code == 200:
            users = response.json()
            
            for user in users:
                jellyfin_user_id = user.get('Id')
                email = user.get('Name')
                is_admin = user.get('Policy', {}).get('IsAdministrator', False)
                
                print(f"Processing user: ID={jellyfin_user_id}, Email={email}, IsAdmin={is_admin}")
                
                try:
                    # Try to get existing user by jellyfin_user_id first
                    db_user = CustomUser.objects.filter(jellyfin_user_id=jellyfin_user_id).first()
                    if not db_user:
                        # If not found by ID, try by email
                        db_user = CustomUser.objects.filter(email=email).first()
                    
                    if db_user:
                        # Update existing user
                        db_user.jellyfin_user_id = jellyfin_user_id
                        db_user.email = email
                        db_user.is_superuser = is_admin
                        db_user.is_staff = is_admin
                        db_user.save()
                        print(f"Updated existing user: {email} (Admin: {is_admin})")
                    else:
                        # Create new user
                        db_user = CustomUser.objects.create(
                            email=email,
                            jellyfin_user_id=jellyfin_user_id,
                            is_superuser=is_admin,
                            is_staff=is_admin
                        )
                        print(f"Created new user: {email} (Admin: {is_admin})")
                        
                except IntegrityError as e:
                    print(f"Error processing user {email}: {str(e)}")
                    # Try to update existing user if there's a conflict
                    try:
                        db_user = CustomUser.objects.get(email=email)
                        db_user.jellyfin_user_id = jellyfin_user_id
                        db_user.is_superuser = is_admin
                        db_user.is_staff = is_admin
                        db_user.save()
                        print(f"Updated user after conflict: {email} (Admin: {is_admin})")
                    except Exception as e2:
                        print(f"Failed to update user after conflict: {str(e2)}")
                    continue
                    
            return True
            
        else:
            print(f"Failed to retrieve users: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"Error in sync_users: {str(e)}")
        return False




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
        latest_movies = [item for item in items if item.get('Type') == 'Movie'][:6]
        # Filter for series only and limit to 4
        latest_shows = [item for item in items if item.get('Type') == 'Series'][:6]

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
    virtual_folders_url = f'{server_url}/Library/VirtualFolders'  # Endpoint to fetch virtual folders

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
                
                # Fetch list of virtual folders
                folders = []
                folders_response = requests.get(virtual_folders_url, headers=headers)
                if folders_response.status_code == 200:
                    folders_data = folders_response.json()
                    folders = [folder['Name'] for folder in folders_data]  # Only get the 'Name' of each folder

                context = {
                    'user_data': user_data,
                    'folders': folders,  # Pass the folders to the template
                }
                print(folders)
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
                    'EnableAllFolders': bool(request.POST.get('enableallfolders', False)),
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
                'EnableAllFolders': bool(request.POST.get('enableallfolders', False)),
            }

            # If EnableAllFolders is false, include selected folders
            if not updated_policy_data['EnableAllFolders']:
                selected_folders = request.POST.getlist('selected_folders')
                updated_policy_data['SelectedFolders'] = selected_folders

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
            email = request.POST.get('email')
            first_name = request.POST.get('first_name')
            last_name = request.POST.get('last_name')
            password = request.POST.get('password')
            # Check user limit based on function settings (optional)
            # if is_user_limit_exceeded():
            #     messages.error(request, 'User creation failed. Maximum user limit reached.')
            #     return redirect('view_users')  # Redirect to user management page

            # Construct the new user data based on the form input values
            new_user_data = {
                'Name': email,
                'Password': password,

                # Add other required fields as per your Jellyfin API documentation
            }
            # Send a POST request to create a new user
            response = requests.post(create_user_url, json=new_user_data, headers=headers)

            if response.status_code == 200:
                jellyfin_user_id = response.json().get('Id')
                user = CustomUser.objects.create_user(email=email, password=password, jellyfin_user_id=jellyfin_user_id, first_name=first_name, last_name=last_name)

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
        return JsonResponse({
            'success': False,
            'error': 'No access token found in session. Please log in first.'
        }, status=401)

    config = Config.objects.first()
    if not config:
        return JsonResponse({
            'success': False,
            'error': 'Configuration error: No Jellyfin server URL configured.'
        }, status=400)

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
            if user_response.status_code != 200:
                return JsonResponse({
                    'success': False,
                    'error': f'Failed to fetch user details: {user_response.status_code}'
                }, status=400)

            user_data = user_response.json()
            username = user_data.get('Name')

            # Delete from Jellyfin
            response = requests.delete(delete_user_url, headers=headers)
            if response.status_code != 204:
                return JsonResponse({
                    'success': False,
                    'error': f'Failed to delete user from Jellyfin: {response.status_code}'
                }, status=400)

            # Delete from Django
            try:
                django_user = CustomUser.objects.get(jellyfin_user_id=user_id)
                django_user.delete()
                log_action('DELETED', f"User '{username}' deleted successfully", request.user)
            except CustomUser.DoesNotExist:
                log_action('DELETED', f"User '{username}' deleted from Jellyfin only", request.user)

            # Sync users after deletion
            sync_users(server_url, access_token)

            return JsonResponse({
                'success': True,
                'message': f"User '{username}' successfully deleted."
            })

        except requests.RequestException as e:
            log_action('ERROR', f"Failed to delete user: {str(e)}", request.user)
            return JsonResponse({
                'success': False,
                'error': f'Failed to connect to Jellyfin server: {str(e)}'
            }, status=500)

        except Exception as e:
            log_action('ERROR', f"Unexpected error while deleting user: {str(e)}", request.user)
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)

    return JsonResponse({
        'success': False,
        'error': 'Method not allowed'
    }, status=405)


@login_required
def invitation_list(request):
    user = request.user
    if user.is_superuser:
        invitations = Invitation.objects.all()
    else:
        invitations = Invitation.objects.filter(user=user)
    
    return render(request, 'invitation_list.html', {'invitations': invitations})


@login_required
@superuser_required
def create_invitation(request):
    if request.method == 'POST':
        try:
            # Retrieve the configuration instance
            config = Config.objects.first()
            if not config or not config.invite_code:
                return JsonResponse({
                    "success": False,
                    "error": "No invite code found in the configuration. Please set an invite code in the admin panel."
                }, status=400)

            # Hardcoded values for the invitation
            invite_code = config.invite_code
            max_users = 500
            used_count = 0
            expiry = None  # Add specific datetime if needed
            user = get_object_or_404(CustomUser, pk=1)  # Adjust to select the correct user

            # Create the invitation
            invitation = Invitation.objects.create(
                invite_code=invite_code,
                max_users=max_users,
                used_count=used_count,
                expiry=expiry,
                user=user,
            )

            return JsonResponse({
                "success": True,
                "message": f"Invitation {invitation.invite_code} created successfully.",
            })

        except Exception as e:
            return JsonResponse({
                "success": False,
                "error": f"An unexpected error occurred: {str(e)}"
            }, status=500)

    return JsonResponse({
        "success": False,
        "error": "Invalid request method. Only POST requests are allowed.",
    }, status=405)

@login_required
@superuser_required
def invitation_delete(request, invite_code):
    if request.method == 'POST':
        try:
            invitation = get_object_or_404(Invitation, invite_code=invite_code)
            invitation.delete()
            
            # Log the deletion
            LogEntry.objects.create(
                action='DELETED',
                    user=request.user,
                message=f'Deleted invitation code: {invite_code}'
            )
            
            return JsonResponse({
                'success': True,
                'message': 'Invitation deleted successfully'
            })
            
        except Invitation.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Invitation not found'
            }, status=404)
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    
    return JsonResponse({
        'success': False,
        'error': 'Method not allowed'
    }, status=405)
    
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
        return redirect('enter_invite')

    if not invitation.has_space_left():
        messages.error(request, "No spaces left for this invitation code.")
        return redirect('enter_invite')

    if invitation.is_expired():
        messages.error(request, "Invitation code has expired.")
        return redirect('enter_invite')

    if request.method == 'POST':
        email = request.POST.get('email')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')

        # Check if email is blacklisted
        if is_email_blacklisted(email):
            messages.error(request, "This email address has been banned from registration.")
            log_action('WARNING', f'Blocked registration attempt from blacklisted email: {email}', invitation.user)
            return redirect('enter_invite')

        # Check if the username (email) is already taken in Jellyfin
        access_token = config.jellyfin_api_key
        server_url = config.server_url
        user_check_url = f"{server_url}/Users/{email}"
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
            log_message = (f"Failed to check username: {str(e)}")
            LogEntry.objects.create(
                action='ERROR',
                user=invitation.user,
                message=log_message
            )
            return redirect('enter_invite')

        # Check if passwords match
        if password != password2:
            messages.error(request, "Passwords do not match.")
            return redirect('enter_invite')

        # Create Jellyfin user via API
        jellyfin_user_data = {
            'Name': email,
            'Password': password,
            'EnableAutoLogin': True
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
            user = CustomUser.objects.create_user(email=email, password=password, jellyfin_user_id=jellyfin_user_id, first_name=first_name, last_name=last_name)
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
def settings(request):
    config = Config.objects.first()
    email_settings = EmailSettings.objects.first()
    
    if request.method == 'POST':
        if 'update_jellyfin' in request.POST:
            # Update only Jellyfin settings
            config.server_url = request.POST.get('server_url')
            config.jellyfin_api_key = request.POST.get('jellyfin_api_key')
            config.save()
            messages.success(request, 'Jellyfin settings updated successfully.')
            
        elif 'update_jellyseerr' in request.POST:
            # Update only Jellyseerr settings
            config.jellyseerr_url = request.POST.get('jellyseerr_url')
            config.jellyseerr_api_key = request.POST.get('jellyseerr_api_key')
            config.save()
            messages.success(request, 'Jellyseerr settings updated successfully.')
            
        elif 'update_tmdb' in request.POST:
            # Update only TMDB settings
            config.tmdb_access_token = request.POST.get('tmdb_access_token')
            config.tmdb_api_key = request.POST.get('tmdb_api_key')
            config.save()
            messages.success(request, 'TMDB settings updated successfully.')
            
        elif 'update_email' in request.POST:
            email_form = EmailSettingsForm(request.POST, instance=email_settings)
            if email_form.is_valid():
                email_form.save()
                from . import email_config
                email_config.update_email_settings()
                messages.success(request, 'Email settings updated successfully.')
        
        return redirect('settings')

    context = {
        'config': config,
        'email_form': EmailSettingsForm(instance=email_settings)
    }
    return render(request, 'settings.html', context)

@login_required
@superuser_required
def test_email(request):
    if request.method == 'POST':
        try:
            send_mail(
                'Test Email from Jellycontrol',
                'This is a test email from your Jellycontrol installation.',
                settings.EMAIL_HOST_USER,
                [request.user.email],
                fail_silently=False,
            )
            return JsonResponse({'success': True})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@login_required
@superuser_required
def download_database(request):
    db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'db.sqlite3')
    try:
        if os.path.exists(db_path):
            # Log the successful download action
            LogEntry.objects.create(
                action='DOWNLOAD',
                user=request.user,
                message=f"Database downloaded successfully."
            )
            response = FileResponse(open(db_path, 'rb'), as_attachment=True, filename='db.sqlite3')
            return response
        else:
            messages.error(request, "Database file not found.")
            # Log the error when the file is not found
            LogEntry.objects.create(
                action='ERROR',
                user=request.user,
                message="Database file not found."
            )
            return redirect('settings')
    except Exception as e:
        messages.error(request, f"Error while downloading database: {str(e)}")
        # Log the error that occurred during download
        LogEntry.objects.create(
            action='ERROR',
            user=request.user,
            message=f"Failed to download database: {str(e)}"
        )
        return redirect('settings')


@csrf_exempt
@login_required
@superuser_required
def upload_database(request):
    if request.method == 'POST' and 'database' in request.FILES:
        db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'db.sqlite3')
        backup_db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'db_backup.sqlite3')
        uploaded_file = request.FILES['database']

        # Create a backup of the current database
        try:
            shutil.copy2(db_path, backup_db_path)  # Make a backup of the current DB
            LogEntry.objects.create(
                action='BACKUP',
                user=request.user,
                message="Database backup created successfully."
            )
        except Exception as e:
            messages.error(request, f"Failed to create database backup: {str(e)}")
            LogEntry.objects.create(
                action='ERROR',
                user=request.user,
                message=f"Failed to create database backup: {str(e)}"
            )
            return redirect('settings')

        try:
            # Save the uploaded database
            with open(db_path, 'wb') as f:
                for chunk in uploaded_file.chunks():
                    f.write(chunk)

            # Run migrations after successful upload
            call_command('makemigrations')  # Create migration files (optional, depending on your setup)
            call_command('migrate')  # Apply migrations

            messages.success(request, "Database uploaded and migrations applied successfully.")
            LogEntry.objects.create(
                action='UPLOAD',
                user=request.user,
                message="Database uploaded and migrations applied successfully."
            )
        except Exception as e:
            # Restore the backup database in case of any failure
            shutil.copy2(backup_db_path, db_path)  # Revert to the backup
            messages.error(request, f"Migration failed and the previous database has been restored: {str(e)}")
            LogEntry.objects.create(
                action='ERROR',
                user=request.user,
                message=f"Failed to upload database and reverted to backup: {str(e)}"
            )
        finally:
            # Clean up the backup if everything was successful
            if os.path.exists(backup_db_path):
                os.remove(backup_db_path)

        return redirect('settings')

    messages.error(request, "Invalid request.")
    LogEntry.objects.create(
        action='ERROR',
        user=request.user,
        message="Invalid request for database upload."
    )
    return redirect('settings')

@login_required
@superuser_required
def logs_view(request):  # Changed from logs to logs_view
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        search_term = request.GET.get('search', '').lower()
        # Get all logs and filter in memory
        all_logs = LogEntry.objects.all().order_by('-created_at')
        
        if search_term:
            filtered_logs = [
                log for log in all_logs if (
                    search_term in log.action.lower() or
                    search_term in str(log.user).lower() or
                    search_term in log.message.lower() or
                    search_term in log.created_at.strftime("%Y-%m-%d %H:%M:%S").lower()
                )
            ]
        else:
            filtered_logs = all_logs

        paginator = Paginator(filtered_logs, 25)  # Show 25 logs per page
        page_number = request.GET.get('page', 1)
        page_obj = paginator.get_page(page_number)

        html = render_to_string(
            'logs_table.html',  # We'll create this partial template
            {'page_obj': page_obj},
            request=request
        )
        
        return JsonResponse({
            'html': html,
            'has_next': page_obj.has_next(),
            'has_previous': page_obj.has_previous(),
            'current_page': page_obj.number,
            'total_pages': paginator.num_pages,
            'total_results': len(filtered_logs)
        })

    # Regular page load
    logs = LogEntry.objects.all().order_by('-created_at')
    paginator = Paginator(logs, 25)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    return render(request, 'logs.html', {'page_obj': page_obj})




@login_required
def movie_list(request):
    try:
        # Get configuration with error handling
        config = Config.objects.first()
        if not config:
            messages.error(request, "Configuration not found.")
            return redirect('home')

        server_url = config.server_url.rstrip('/')
        api_key = config.jellyfin_api_key
        tmdb_api_key = config.tmdb_api_key

        # Get access token with error handling
        access_token = request.session.get('jellyfin_access_token')
        if not access_token:
            messages.error(request, "Session expired. Please login again.")
            return redirect('login')

        headers = {
            'X-MediaBrowser-Token': api_key,
        'X-Emby-Token': access_token,
        }

        # Handle AJAX search requests
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            search_term = request.GET.get('search', '').strip()
            
            # First, get ALL movies from Jellyfin to have their IDs available
            all_movies_response = requests.get(
                f'{server_url}/Items',
                headers=headers,
                params={
        'IncludeItemTypes': 'Movie',
                    'Recursive': 'true',
                    'Fields': 'PrimaryImageAspectRatio,BasicSyncInfo,ImageTags,ProviderIds',
                    'ImageTypeLimit': 1,
                    'EnableImageTypes': 'Primary,Backdrop,Banner,Thumb',
                }
            )
            all_movies_response.raise_for_status()
            all_jellyfin_movies = all_movies_response.json().get('Items', [])

            # Create a mapping of TMDB IDs to Jellyfin movies
            jellyfin_movie_map = {}
            for movie in all_jellyfin_movies:
                provider_ids = movie.get('ProviderIds', {})
                tmdb_id = provider_ids.get('Tmdb')
                if tmdb_id:
                    jellyfin_movie_map[str(tmdb_id)] = movie

            # Search TMDB first to get the correct ID
            if tmdb_api_key:
                tmdb_url = 'https://api.themoviedb.org/3/search/movie'
                tmdb_params = {
                    'api_key': tmdb_api_key,
                    'query': search_term,
                    'language': 'en-US',
                    'page': 1
                }
                
                tmdb_response = requests.get(tmdb_url, params=tmdb_params)
                tmdb_response.raise_for_status()
                tmdb_data = tmdb_response.json()
                
                # Process TMDB results
                tmdb_movies = []
                jellyfin_matches = []

                for movie in tmdb_data.get('results', [])[:6]:
                    if not movie['title'] or 'untitled' in movie['title'].lower():
                        continue
                    
                    tmdb_id = str(movie['id'])
                    
                    # Check if we have this movie in Jellyfin
                    if tmdb_id in jellyfin_movie_map:
                        jellyfin_matches.append(jellyfin_movie_map[tmdb_id])
                    else:
                        if not movie['release_date']:
                            continue
                        tmdb_movies.append({
                            'Name': movie['title'],
                            'ProductionYear': movie['release_date'][:4] if movie['release_date'] else None,
                            'ImageTags': {'Primary': True} if movie['poster_path'] else {},
                            'Id': f"tmdb_{movie['id']}",
                            'PosterPath': movie['poster_path'],
                            'IsFromTMDB': True,
                            'TMDBId': tmdb_id
                        })
                
                # If we found matches in Jellyfin, use those; otherwise, show TMDB results
                if jellyfin_matches:
                    movies = jellyfin_matches
                else:
                    movies = tmdb_movies

            html = render_to_string(
                'movie_grid.html',
                {
                    'movies': movies,
                    'config': config,
                    'tmdb_base_url': 'https://image.tmdb.org/t/p/w500',
                    'jellyseerr_url': config.jellyseerr_url  # Add this line
                },
                request=request
            )

            return JsonResponse({
                'html': html,
                'total_results': len(movies),
                'has_tmdb_results': bool(tmdb_movies) if 'tmdb_movies' in locals() else False
            })

        # Regular page load
        response = requests.get(
            f'{server_url}/Items',
            headers=headers,
            params={
                'IncludeItemTypes': 'Movie',
                'Recursive': 'true',
                'Fields': 'PrimaryImageAspectRatio,BasicSyncInfo,ImageTags',
                'ImageTypeLimit': 1,
                'EnableImageTypes': 'Primary,Backdrop,Banner,Thumb',
                'SortBy': 'SortName',
                'SortOrder': 'Ascending'
            }
        )
        response.raise_for_status()
        movies = response.json().get('Items', [])
        
        # Mark all movies as not from TMDB (they're from Jellyfin)
        for movie in movies:
            movie['IsFromTMDB'] = False
        
        paginator = Paginator(movies, 50)
        page_number = request.GET.get('page', 1)
        page_obj = paginator.get_page(page_number)

        return render(request, 'movie_list.html', {
        'page_obj': page_obj,
            'config': config
    })

    except Exception as e:
        messages.error(request, f"Error loading movies: {str(e)}")
        return redirect('home')


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
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            new_password = data.get('password')
            
            if not new_password:
                return JsonResponse({
                    'success': False,
                    'error': 'Password is required'
                }, status=400)

            # Get the user and config
            user = get_object_or_404(CustomUser, jellyfin_user_id=user_id)
            config = get_object_or_404(Config, pk=1)
            
            # Get Jellyfin token
            jellyfin_token = request.session.get('jellyfin_access_token')
            if not jellyfin_token:
                return JsonResponse({
                    'success': False,
                    'error': 'Jellyfin authentication token not found'
                }, status=401)
        
            # Define headers for Jellyfin API
            headers = {
                'Authorization': f'MediaBrowser Token={jellyfin_token}',
                'Content-Type': 'application/json'
            }
        
            # Step 1: Reset password in Jellyfin
            reset_url = f'{config.server_url}/Users/{user_id}/Password'
            reset_payload = {
                'ResetPassword': True,
                'CurrentPw': None,
                'NewPw': None
            }

            reset_response = requests.post(reset_url, json=reset_payload, headers=headers)
            if reset_response.status_code != 204:
                return JsonResponse({
                    'success': False,
                    'error': 'Failed to initiate password reset in Jellyfin'
                }, status=400)

            # Step 2: Set new password in Jellyfin
            password_payload = {
                'ResetPassword': False,
                'CurrentPw': None,
                'NewPw': new_password
            }

            password_response = requests.post(reset_url, json=password_payload, headers=headers)
            if password_response.status_code != 204:
                return JsonResponse({
                    'success': False,
                    'error': 'Failed to set new password in Jellyfin'
                }, status=400)

            # Step 3: Update Django user password
            user.set_password(new_password)
            user.save()
            
            # Log the password reset
            LogEntry.objects.create(
                action='INFO',
                user=request.user,
                message=f'Password reset for user {user.email}'
            )
            
            return JsonResponse({'success': True})
            
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
            
    return JsonResponse({
        'success': False,
        'error': 'Method not allowed'
    }, status=405)

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






@login_required
def series_list(request):
    access_token = request.session.get('jellyfin_access_token')
    if not access_token:
        return redirect('login')
    
    try:
        config = Config.objects.first()
        server_url = config.server_url
    except Config.DoesNotExist:
        return render(request, 'error.html', {'error': 'Server configuration not found.'})
    
    series_url = f"{server_url}/Users/{request.user.jellyfin_user_id}/Items"

    headers = {
                'X-MediaBrowser-Token': access_token
    }

    params = {
        'IncludeItemTypes': 'Series',
                'Recursive': 'true',
        'Fields': 'PrimaryImageAspectRatio,BasicSyncInfo,ImageTags,Overview,ProductionYear',
                'ImageTypeLimit': 1,
                'EnableImageTypes': 'Primary',
        'SortBy': 'SortName',
        'SortOrder': 'Ascending'
    }

    try:
        response = requests.get(series_url, headers=headers, params=params)
        response.raise_for_status()
        series_data = response.json().get('Items', [])
    except requests.exceptions.RequestException as e:
        return render(request, 'error.html', {'error': str(e)})

    # Handle search
    search_query = request.GET.get('search', '').lower()
    if search_query:
        series_data = [show for show in series_data if search_query in show.get('Name', '').lower()]

    # Pagination
    paginator = Paginator(series_data, 24)  # Show 24 series per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'tv-shows.html', {
        'page_obj': page_obj,
        'config': config,
        'search_query': search_query
    })


@login_required
def series_detail(request, movie_id):
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
    season_url = f'{server_url}/Shows/{movie_id}/Seasons'
    try:
        # Fetch movie data
        response = requests.get(movie_url, headers=headers)
        response.raise_for_status()
        movie_data = response.json()

        # Fetch season data
        response = requests.get(season_url, headers=headers)
        response.raise_for_status()
        season_data = response.json().get('Items', [])  # Assuming season data is under 'Items'
    except requests.RequestException as e:
        messages.error(request, f"Error fetching movie details: {str(e)}")
        return redirect('home')

    return render(request, 'series_detail.html', {'movie': movie_data, 'season_data': season_data, 'config': config})



#### error pages ####


def custom_bad_request(request, exception):
    return render(request, 'errors/400.html', status=400)

def custom_permission_denied(request, exception):
    return render(request, 'errors/403.html', status=403)

def custom_page_not_found(request, exception):
    return render(request, 'errors/404.html', status=404)

def custom_server_error(request):
    return render(request, 'errors/500.html', status=500)


User = get_user_model()


def password_reset_request(request):
    if request.method == "POST":
        email = request.POST.get("email")
        try:
            user = User.objects.get(email=email)
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            reset_url = request.build_absolute_uri(reverse('password_reset_confirm', args=[uid, token]))

            # Render the email HTML template
            email_html_content = render_to_string("emails/password_reset_email.html", {
                'user': user,
                'reset_url': reset_url,
            })

            # Create and send email
            email_message = EmailMessage(
                subject="Password Reset Request",
                body=email_html_content,
                from_email="admin@example.com",
                to=[email],
            )
            email_message.content_subtype = "html"  # This is important to set HTML content
            email_message.send()

            messages.success(request, "Password reset link sent to your email.")
            return redirect("login")
        except User.DoesNotExist:
            messages.error(request, "User with the provided email does not exist.")
    return render(request, "registration/password_reset_request.html")



def password_reset_confirm(request, uidb64, token):
    try:
        # Decode the user id
        uid = urlsafe_base64_decode(uidb64).decode()
        user = CustomUser.objects.get(pk=uid)
        
        if request.method == 'POST':
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')
            
            if not password or not confirm_password:
                messages.error(request, 'Both password fields are required.')
                return redirect('password_reset_confirm', uidb64=uidb64, token=token)
                
            if password != confirm_password:
                messages.error(request, 'Passwords do not match.')
                return redirect('password_reset_confirm', uidb64=uidb64, token=token)
            
            if default_token_generator.check_token(user, token):
                # Get Jellyfin config
                config = Config.objects.first()
                if not config:
                    messages.error(request, 'Jellyfin configuration not found.')
                    return redirect('login')

                try:
                    # First update password in Jellyfin
                    reset_url = f'{config.server_url}/Users/{user.jellyfin_user_id}/Password'
                    
                    # Step 1: Reset the password
                    reset_payload = {
                        'ResetPassword': True
                    }
                    headers = {
                        'Content-Type': 'application/json',
                        'X-Emby-Token': config.jellyfin_api_key
                    }
                    
                    reset_response = requests.post(reset_url, json=reset_payload, headers=headers)
                    if reset_response.status_code != 204:
                        raise Exception(f'Failed to reset Jellyfin password: {reset_response.status_code}')

                    # Step 2: Set the new password
                    new_password_payload = {
                        'ResetPassword': False,
                        'NewPw': password
                    }
                    
                    set_response = requests.post(reset_url, json=new_password_payload, headers=headers)
                    if set_response.status_code != 204:
                        raise Exception(f'Failed to set new Jellyfin password: {set_response.status_code}')

                    # If Jellyfin update successful, update Django password
                    user.set_password(password)
                    user.save()
                    
                    messages.success(request, 'Password has been reset successfully.')
                    log_action('INFO', f'Password reset successful for user {user.email}', user)
                    return redirect('login')
                    
                except Exception as e:
                    messages.error(request, f'Failed to reset password: {str(e)}')
                    log_action('ERROR', f'Password reset failed for user {user.email}: {str(e)}', user)
                    return redirect('password_reset')
            else:
                messages.error(request, 'Password reset link is invalid or has expired.')
                return redirect('password_reset')
                
        return render(request, 'registration/password_reset_confirm.html', {
            'uidb64': uidb64,
            'token': token
        })
        
    except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist) as e:
        messages.error(request, 'Invalid password reset link.')
        return redirect('password_reset')

    

## request views ##

@login_required
@superuser_required
def list_requests(request):
    #View to retrieve a list of all requests from the Overseer API and log the actions.
    url = "https://request.ccmediastreaming.com/api/v1/request"
    config = Config.objects.first()
    
    api_key = config.JELLYSEER_API_KEY
    headers = {
        "X-Api-Key": api_key
    }

    try:
        # Make the API call to Overseer
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        requests_data = response.json()

        # Access the 'results' field from the response
        requests_list = requests_data.get('results', [])

        # Log the successful data retrieval
        log_entry = LogEntry(
            action='INFO',
            user=request.user,
            message='Successfully retrieved requests from Jellyseer API.',
        )
        log_entry.save()
        print(requests_data)
        # Pass the requests list to the template
        return render(request, 'requests_list.html', {'requests': requests_list})

    except requests.exceptions.HTTPError as http_err:
        log_entry = LogEntry(
            action='ERROR',
            user=request.user,
            message=f'HTTP error occurred: {str(http_err)}',
        )
        log_entry.save()
        return render(request, 'requests_list.html', {'error': str(http_err)})

    except Exception as err:
        log_entry = LogEntry(
            action='ERROR',
            user=request.user,
            message=f'An error occurred: {str(err)}',
        )
        log_entry.save()
        return render(request, 'requests_list.html', {'error': str(err)})

    except Exception as err:
        # Log any other exceptions
        log_entry = LogEntry(
            action='ERROR',
            user=request.user,
            message=f'An error occurred: {str(err)}',
        )
        log_entry.save()
        return render(request, 'requests_list.html', {'error': str(err)})

@login_required
@superuser_required
def check_for_updates(request):
    # Define your GitHub repository
    repo = "pcmodder2001/jellycontrol"
    
    # Fetch the latest release version from GitHub
    latest_url = f"https://api.github.com/repos/{repo}/releases/latest"
    all_releases_url = f"https://api.github.com/repos/{repo}/releases"
    
    # Get latest release
    latest_response = requests.get(latest_url)
    
    if latest_response.status_code == 200:
        latest_version = latest_response.json().get("tag_name")
        
        # Compare versions
        if latest_version and latest_version != settings.APP_VERSION:
            update_available = True
            message = f"A newer version ({latest_version}) is available."
        else:
            update_available = False
            message = "You are up-to-date with version " + settings.APP_VERSION
    else:
        update_available = False
        message = "Failed to fetch the latest version information."
    
    # Fetch all releases
    all_releases_response = requests.get(all_releases_url)
    
    if all_releases_response.status_code == 200:
        releases = all_releases_response.json()
        versions = [
            {'tag': release['tag_name'], 'url': release['html_url']}
            for release in releases
        ]
    else:
        versions = []
    
    context = {
        'update_available': update_available,
        'message': message,
        'current_version': settings.APP_VERSION,
        'latest_version': latest_version if latest_response.status_code == 200 else None,
        'versions': versions,
    }
    
    return render(request, "check_for_updates.html", context)


@login_required
@superuser_required
@require_POST
def update_is_disabled(request):
    data = json.loads(request.body)
    user_id = data.get('user_id')
    is_disabled = data.get('is_disabled', False)

    access_token = request.session.get('jellyfin_access_token')
    if not access_token:
        return JsonResponse({'success': False, 'error': "No access token found in session."})

    config = Config.objects.first()
    if not config:
        return JsonResponse({'success': False, 'error': "No Jellyfin server URL configured."})

    server_url = config.server_url
    user_url = f'{server_url}/Users/{user_id}'  # Endpoint to get user data, including policy info

    headers = {
        'X-Emby-Token': access_token,
        'Content-Type': 'application/json',
    }

    try:
        # Fetch full user data to get PasswordResetProviderId and AuthenticationProviderId
        response = requests.get(user_url, headers=headers)
        if response.status_code != 200:
            return JsonResponse({
                'success': False,
                'error': f"Failed to fetch current user data: {response.status_code} - {response.text}"
            })

        user_data = response.json()
        policy = user_data.get('Policy', {})
        password_reset_provider_id = policy.get('PasswordResetProviderId', 'default_provider_id')
        authentication_provider_id = policy.get('AuthenticationProviderId', 'default_auth_provider_id')

        # Prepare updated policy data with only the is_disabled field and the fetched values
        updated_policy_data = {
            'IsDisabled': is_disabled,
            'PasswordResetProviderId': password_reset_provider_id,
            'AuthenticationProviderId': authentication_provider_id,
        }

        # Update user policy data
        update_policy_url = f'{server_url}/Users/{user_id}/Policy'
        response = requests.post(update_policy_url, json=updated_policy_data, headers=headers)
        if response.status_code == 204:
            #messages.success(request, "User updated")
            return JsonResponse({'success': True})
        else:
            return JsonResponse({
                'success': False,
                'error': f"Failed to update user policy: {response.status_code} - {response.text}"
            })

    except requests.RequestException as e:
        return JsonResponse({'success': False, 'error': f"Failed to connect to Jellyfin server: {str(e)}"})

def log_error(action, message, user=None):
    """Helper function to log errors"""
    LogEntry.objects.create(
        action=action,
        message=message,
        user=user
    )

def log_info(action, message, user=None):
    """Helper function to log information"""
    LogEntry.objects.create(
        action=action,
        message=message,
        user=user
    )

def normalize_title(title):
    """Helper function to normalize movie titles for comparison"""
    # Convert numbers to words (up to 10)
    number_map = {
        '0': 'zero', '1': 'one', '2': 'two', '3': 'three', '4': 'four',
        '5': 'five', '6': 'six', '7': 'seven', '8': 'eight', '9': 'nine'
    }
    
    # Normalize the title
    title = title.lower()
    
    # Remove special characters and extra whitespace
    title = re.sub(r'[^\w\s]', '', title)
    title = ' '.join(title.split())
    
    # Create word and number versions
    title_with_numbers = title
    title_with_words = title
    
    # Replace numbers with words and vice versa
    for num, word in number_map.items():
        title_with_words = re.sub(r'\b' + num + r'\b', word, title_with_words)
        title_with_numbers = re.sub(r'\b' + word + r'\b', num, title_with_numbers)
    
    # Remove common words
    words_to_remove = ['untitled', 'the', 'a', 'an', 'spinoff', 'spin-off', 'none']
    words = [w for w in title.split() if w.lower() not in words_to_remove]
    
    return {
        'original': title,
        'with_numbers': title_with_numbers,
        'with_words': title_with_words,
        'words': words
    }

def titles_match(search_title, movie_title):
    """Check if titles match using various methods"""
    search_norm = normalize_title(search_title)
    movie_norm = normalize_title(movie_title)
    
    # Direct matches
    if any(s in movie_norm['original'] for s in [search_norm['original'], search_norm['with_numbers'], search_norm['with_words']]):
        return True
    
    # Word matches (check if all search words appear in movie title)
    search_words = set(search_norm['words'])
    movie_words = set(movie_norm['words'])
    
    # Check if all search words are in movie title
    if all(any(search_word in movie_word for movie_word in movie_words) for search_word in search_words):
        return True
    
    return False

@login_required
def proxy_jellyseerr_request(request):
    try:
        # Get Jellyseerr configuration
        config = Config.objects.first()
        if not config or not config.jellyseerr_url or not config.jellyseerr_api_key:
            return JsonResponse({
                'success': False,
                'error': 'Jellyseerr configuration is missing'
            }, status=400)

        # Get request data
        data = json.loads(request.body)
        
        # Check if media already exists in Jellyseerr
        media_type = data.get('mediaType', '')
        media_id = data.get('mediaId')
        check_url = f"{config.jellyseerr_url}/api/v1/media/{media_type}/{media_id}"
        
        headers = {
            'X-Api-Key': config.jellyseerr_api_key,
            'Content-Type': 'application/json'
        }

        # Check if media already exists
        check_response = requests.get(check_url, headers=headers)
        if check_response.status_code == 200:
            media_data = check_response.json()
            # Check both status and existing tvdbId
            if media_data.get('mediaInfo', {}).get('status') == 'PENDING':
                return JsonResponse({
                    'success': False,
                    'error': 'This media has already been requested'
                }, status=409)

        # Prepare request data - only include tvdbId for TV shows
        request_data = {
            'mediaType': media_type,
            'mediaId': media_id,
            'is4k': data.get('is4k', False),
            'serverId': 1,
            'profileId': 1,
            'rootFolder': data.get('rootFolder', ''),
            'languageProfileId': data.get('languageProfileId', 1),
            'userId': request.user.id
        }

        # Only add tvdbId and seasons for TV shows
        if media_type.lower() == 'tv':
            request_data['tvdbId'] = data.get('tvdbId')
            request_data['seasons'] = data.get('seasons', [])

        # Make the request
        request_url = f"{config.jellyseerr_url}/api/v1/request"
        response = requests.post(request_url, headers=headers, json=request_data)
        
        if response.status_code in [200, 201]:
            log_action('INFO', f'Media request successful: {media_type} ID {media_id}', request.user)
            return JsonResponse({
                'success': True,
                'message': 'Request submitted successfully'
            })
        else:
            error_message = response.json().get('message', 'Unknown error occurred')
            if 'UNIQUE constraint failed: media.tvdbId' in error_message:
                return JsonResponse({
                    'success': False,
                    'error': 'This show has already been requested or added to the library'
                }, status=409)
            log_action('ERROR', f'Media request failed: {error_message}', request.user)
            return JsonResponse({
                'success': False,
                'error': error_message
            }, status=response.status_code)

    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON data'
        }, status=400)
    except Exception as e:
        log_action('ERROR', f'Request proxy error: {str(e)}', request.user)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@login_required
def search_tmdb_shows(request):
    config = Config.objects.first()
    if not config:
        return JsonResponse({'error': 'Configuration not found'}, status=404)

    search_query = request.GET.get('query', '')
    if not search_query:
        return JsonResponse({'results': []})

    try:
        tmdb_url = "https://api.themoviedb.org/3/search/tv"
        headers = {
            "accept": "application/json",
            "Authorization": f"Bearer {config.tmdb_access_token}"
        }
        params = {
            "query": search_query,
            "include_adult": "false",
            "language": "en-US",
            "page": 1
        }

        response = requests.get(tmdb_url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()

        # Transform the results to match your needs
        shows = [{
            'Name': show['name'],
            'ProductionYear': show.get('first_air_date', '')[:4],
            'PosterPath': show.get('poster_path'),
            'TMDBId': show['id'],
            'Overview': show.get('overview', ''),
            'IsFromTMDB': True
        } for show in data.get('results', [])]

        return JsonResponse({
            'results': shows,
            'tmdb_base_url': 'https://image.tmdb.org/t/p/w500'
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@superuser_required
def invitation_create(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            invite_code = data.get('invite_code')
            max_users = int(data.get('max_users', 1))
            expiry = data.get('expiry')
            
            # Debug logging
            print(f"Received data: {data}")
            print(f"Invite code: {invite_code}")
            print(f"Max users: {max_users}")
            print(f"Expiry: {expiry}")
            
            # Validate the data
            if not invite_code:
                return JsonResponse({
                    'success': False,
                    'error': 'Invite code is required'
                }, status=400)
                
            if max_users < 1:
                return JsonResponse({
                    'success': False,
                    'error': 'Max users must be at least 1'
                }, status=400)
            
            # Handle expiry date conversion
            expiry_date = None
            if expiry:
                try:
                    expiry_date = datetime.fromisoformat(expiry.replace('Z', '+00:00'))
                except ValueError:
                    return JsonResponse({
                        'success': False,
                        'error': 'Invalid expiry date format'
                    }, status=400)
            
            # Create the invitation
            invitation = Invitation.objects.create(
                invite_code=invite_code,
                max_users=max_users,
                expiry=expiry_date,
                user=request.user
            )
            
            # Log the creation
            LogEntry.objects.create(
                action='CREATED',
                user=request.user,
                message=f'Created invitation code: {invite_code}'
            )
            
            return JsonResponse({
                'success': True,
                'message': 'Invitation created successfully',
                'invitation': {
                    'code': invitation.invite_code,
                    'max_users': invitation.max_users,
                    'created_at': invitation.created_at.isoformat(),
                    'expiry': invitation.expiry.isoformat() if invitation.expiry else None
                }
            }, status=201)
            
        except json.JSONDecodeError as e:
            print(f"JSON Decode Error: {e}")
            return JsonResponse({
                'success': False,
                'error': 'Invalid JSON data'
            }, status=400)
        except ValueError as e:
            print(f"Value Error: {e}")
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=400)
        except Exception as e:
            # Log the full error
            import traceback
            print(f"Unexpected error: {e}")
            print(traceback.format_exc())
            
            # Log unexpected errors
            LogEntry.objects.create(
                action='ERROR',
                user=request.user,
                message=f'Error creating invitation: {str(e)}'
            )
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    
    return JsonResponse({
        'success': False,
        'error': 'Method not allowed'
    }, status=405)

def generate_api_key():
    """Generate a random API key."""
    length = 32
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

@login_required
@superuser_required
def blacklist_view(request):
    blacklisted_emails = BlacklistedEmail.objects.all()
    return render(request, 'control/blacklist.html', {'blacklisted_emails': blacklisted_emails})

@login_required
@superuser_required
def add_blacklist(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email = data.get('email')
            reason = data.get('reason')

            if not email:
                return JsonResponse({'success': False, 'error': 'Email is required'})

            # Check if email is already blacklisted
            if BlacklistedEmail.objects.filter(email__iexact=email).exists():
                return JsonResponse({'success': False, 'error': 'Email is already blacklisted'})

            BlacklistedEmail.objects.create(
                email=email.lower(),
                reason=reason,
                created_by=request.user
            )

            log_action('INFO', f'Email {email} added to blacklist by {request.user.email}', request.user)
            return JsonResponse({'success': True})

        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'error': 'Invalid JSON data'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})

    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@login_required
@superuser_required
def remove_blacklist(request, blacklist_id):
    if request.method == 'POST':
        try:
            blacklisted_email = get_object_or_404(BlacklistedEmail, id=blacklist_id)
            email = blacklisted_email.email
            blacklisted_email.delete()
            
            log_action('INFO', f'Email {email} removed from blacklist by {request.user.email}', request.user)
            return JsonResponse({'success': True})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})

    return JsonResponse({'success': False, 'error': 'Invalid request method'})

def is_email_blacklisted(email):
    """Helper function to check if an email is blacklisted"""
    return BlacklistedEmail.objects.filter(email__iexact=email).exists()