import os
import sys
from pathlib import Path
from django.core.management import execute_from_command_line
from django.core.wsgi import get_wsgi_application
from waitress import serve
from whitenoise import WhiteNoise
import shutil

def run_server():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'jellyfin_project.settings')
    
    # Create staticfiles directory if it doesn't exist
    BASE_DIR = Path(__file__).resolve().parent
    STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
    
    # Clean up old static files
    if os.path.exists(STATIC_ROOT):
        shutil.rmtree(STATIC_ROOT)
    os.makedirs(STATIC_ROOT, exist_ok=True)
    
    if len(sys.argv) > 1:
        # Handle Django management commands
        execute_from_command_line(sys.argv)
    else:
        try:
            # Collect static files
            print("Collecting static files...")
            sys.argv.extend(['collectstatic', '--noinput'])
            execute_from_command_line(sys.argv)
            sys.argv = sys.argv[:1]
            
            # Get the WSGI application
            print("Starting Waitress server...")
            application = get_wsgi_application()
            
            # Add WhiteNoise for static files
            application = WhiteNoise(application, root=STATIC_ROOT)
            application.add_files(STATIC_ROOT, prefix='static/')
            
            # Run Waitress server
            serve(application, host='0.0.0.0', port=8056, threads=4)
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)

if __name__ == '__main__':
    run_server() 