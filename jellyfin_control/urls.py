from django.urls import path
from . import views

urlpatterns = [
    path('test-email/', views.test_email, name='test_email'),
    path('download-database/', views.download_database, name='download_database'),
    path('upload-database/', views.upload_database, name='upload_database'),
    path('blacklist/', views.blacklist_view, name='blacklist'),
    path('blacklist/add/', views.add_blacklist, name='add_blacklist'),
    path('blacklist/remove/<int:blacklist_id>/', views.remove_blacklist, name='remove_blacklist'),
] 