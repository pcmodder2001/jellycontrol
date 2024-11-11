# myapp/management/commands/check_for_update.py

from django.conf import settings
from django.core.management.base import BaseCommand
import requests

class Command(BaseCommand):
    help = "Checks if a newer version is available on GitHub"

    def handle(self, *args, **kwargs):
        # Define your GitHub repo
        repo = "pcmodder2001/jellycontrol"
        
        # Fetch the latest release version from GitHub
        url = f"https://api.github.com/repos/{repo}/releases/latest"
        print(url)
        response = requests.get(url)
        
        if response.status_code == 200:
            latest_version = response.json().get("tag_name")
            
            # Compare versions
            if latest_version and latest_version != settings.APP_VERSION:
                self.stdout.write(f"Newer version available: {latest_version}")
            else:
                self.stdout.write("You are up-to-date with version " + settings.APP_VERSION)
        else:
            self.stdout.write("Failed to fetch latest version information.")
