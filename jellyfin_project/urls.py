"""
URL configuration for jellyfin_project project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
import os
from django.contrib import admin
from django.urls import path
from jellyfin_control import views
from django.contrib.auth import views as auth_views
from django.conf.urls import handler400, handler403, handler404, handler500
from jellyfin_control.views import custom_bad_request, custom_permission_denied, custom_page_not_found, custom_server_error
from jellyfin_project import settings
from django.conf.urls.static import static
from django.http import FileResponse


urlpatterns = [
    path('admin/', admin.site.urls),
    path('setup/', views.setup, name='setup'),
    path('', views.custom_login, name='login'),
    path('logout/', views.custom_logout, name='logout'),  # Add this line for logout
    path('home/', views.home, name='home'),
    path('accounts/login/', views.custom_login, name='login'),
    path('users/', views.view_users, name='view_users'),
    path('users/<str:user_id>/update/', views.update_user, name='update_user'),
    path('create-user/', views.create_user, name='create_user'),
    path('delete-user/<str:user_id>/', views.delete_user, name='delete_user'),
    path('invitations/', views.invitation_list, name='invitation_list'),
    path('invitations/create/', views.invitation_create, name='invitation_create'),
    path('invitations/delete/<uuid:invitation_id>/', views.invitation_delete, name='invitation_delete'),
    path('register/', views.enter_invite, name='enter_invite'),
    path('register/<str:invite_code>/', views.register, name='register'),
    path('invite/<str:invite_code>/', views.register, name='invite'),
    path('registration_success/', views.registration_success, name='registration_success'),
    path('enter-license-key/', views.enter_license_key, name='enter_license_key'),
    path('revalidate_license-key/', views.revalidate_license, name='revalidate_license'),
    path('view_license/', views.view_license, name='view_license'),
    path('settings/', views.settings_view, name='settings'),
    path('logs/', views.logs_view, name='logs'),
    path('movies/', views.movie_list, name='movie_list'),
    path('movies/<str:movie_id>/', views.movie_detail, name='movie_detail'),
    path('master-reset-password/<str:user_id>/', views.reset_user_password, name='reset_user_password'),
    path('devices/', views.view_devices, name='view_devices'),
    path('sessions/', views.sessions_page, name='sessions_page'),
    path('generate-api-key/', views.generate_api_key_view, name='generate_api_key'),
    path('tv-shows/', views.series_list, name='series_list'),
    path('tv-shows/<str:movie_id>/detail/series', views.series_detail, name='series-detail'),
]



def serve_static(request, path, document_root=None):
    file_path = os.path.join(document_root, path)
    print(f"Serving static file from: {file_path}", flush=True)  # Use flush=True
    return FileResponse(open(file_path, 'rb'))

if settings.DEBUG == False:
    urlpatterns += static(
        settings.STATIC_URL, 
        document_root=settings.STATIC_ROOT, 
        view=serve_static
    )


handler400 = 'jellyfin_control.views.custom_bad_request'
handler403 = 'jellyfin_control.views.custom_permission_denied'
handler404 = 'jellyfin_control.views.custom_page_not_found'
handler500 = 'jellyfin_control.views.custom_server_error'