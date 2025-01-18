# rota/forms.py

from django import forms
from .models import Config, CustomUser, EmailSettings


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

class EmailSettingsForm(forms.ModelForm):
    class Meta:
        model = EmailSettings
        fields = [
            'company_name',
            'from_email',
            'site_url',
            'support_email',
            'smtp_host',
            'smtp_port',
            'smtp_username',
            'smtp_password',
            'use_tls',
            'use_ssl'
        ]
        widgets = {
            'smtp_password': forms.PasswordInput(render_value=True),
            'company_name': forms.TextInput(attrs={'class': 'uk-input'}),
            'from_email': forms.EmailInput(attrs={'class': 'uk-input'}),
            'site_url': forms.URLInput(attrs={'class': 'uk-input'}),
            'support_email': forms.EmailInput(attrs={'class': 'uk-input'}),
            'smtp_host': forms.TextInput(attrs={'class': 'uk-input'}),
            'smtp_port': forms.NumberInput(attrs={'class': 'uk-input'}),
            'smtp_username': forms.TextInput(attrs={'class': 'uk-input'}),
            'smtp_password': forms.PasswordInput(attrs={'class': 'uk-input', 'render_value': True}),
            'use_tls': forms.CheckboxInput(attrs={'class': 'uk-checkbox'}),
            'use_ssl': forms.CheckboxInput(attrs={'class': 'uk-checkbox'})
        }