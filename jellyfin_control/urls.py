from django.urls import path
from . import views

urlpatterns = [
    path('test-email/', views.test_email, name='test_email'),
    path('download-database/', views.download_database, name='download_database'),
    path('upload-database/', views.upload_database, name='upload_database'),
] 