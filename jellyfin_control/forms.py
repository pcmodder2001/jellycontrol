# rota/forms.py

from django import forms
from .models import Config, CustomUser


class ConfigForm(forms.ModelForm):
    class Meta:
        model = Config
        fields = [
            'server_url', 
            'jellyfin_api_key', 
            'invite_code',
            'tmdb_access_token',
            'tmdb_api_key',
            'jellyseerr_url',
            'jellyseerr_api_key'
        ]
        widgets = {
            'server_url': forms.URLInput(attrs={'class': 'uk-input'}),
            'jellyfin_api_key': forms.TextInput(attrs={'class': 'uk-input'}),
            'invite_code': forms.TextInput(attrs={'class': 'uk-input'}),
            'tmdb_access_token': forms.TextInput(attrs={'class': 'uk-input'}),
            'tmdb_api_key': forms.TextInput(attrs={'class': 'uk-input'}),
            'jellyseerr_url': forms.URLInput(attrs={'class': 'uk-input'}),
            'jellyseerr_api_key': forms.TextInput(attrs={'class': 'uk-input'}),
        }