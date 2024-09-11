from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, Config, Invitation, License, Function, LogEntry

class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ('email', 'first_name', 'last_name', 'is_active', 'is_staff', 'jellyfin_user_id')
    ordering = ('email',)  # Specify a default ordering, e.g., by email

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal Info', {'fields': ('first_name', 'last_name', 'jellyfin_user_id')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login',)}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'is_staff', 'is_superuser'),
        }),
    )

admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(Config)
admin.site.register(Invitation)
admin.site.register(License)
admin.site.register(Function)
admin.site.register(LogEntry)