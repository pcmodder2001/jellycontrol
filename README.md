Jellyfin Control App
This is a Django-based web application for managing users and interacting with a Jellyfin media server. The application allows admins to create users via Jellyfin API, while users can register themselves using invitation codes.

Features
Jellyfin Integration: Manage users directly from Jellyfin within the Django application.
User Registration via Invitation: Users can register using a custom invite code system, ensuring limited and controlled access.
Custom User Management: Admins can create, view, and manage users from within the app, synced with Jellyfin.
API Key Management: Automatically handle Jellyfin API key creation and management through the setup process.
Error Logging: Custom log model captures significant user actions and system errors.
Prerequisites
Before running this project, ensure you have the following installed:

Python 3.8+
Django 3.2+
PostgreSQL or another supported database
Jellyfin server
Jellyfin API key
Installation
Clone the repository:

bash
Copy code
git clone https://github.com/your-repo/jellyfin-control-app.git
cd jellyfin-control-app
Create a virtual environment:

bash
Copy code
python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
Install the dependencies:

bash
Copy code
pip install -r requirements.txt
Configure environment variables:

Create a .env file in the root directory, with the following values:

env
Copy code
SECRET_KEY=your-django-secret-key
DEBUG=True  # Set to False in production
ALLOWED_HOSTS=localhost, 127.0.0.1
DATABASE_URL=postgres://user:password@localhost:5432/dbname
Run database migrations:

bash
Copy code
python manage.py migrate
Create a superuser:

bash
Copy code
python manage.py createsuperuser
Run the development server:

bash
Copy code
python manage.py runserver
Jellyfin Setup
To integrate with Jellyfin:

Go to the Config section of the app after setup.
Add the Jellyfin server URL and API key.
Complete the multi-step setup wizard to sync users and generate API keys.
Usage
Admin User Management
Admins can create and manage users using the create_user view.
The system logs all major actions such as user creation or errors in the custom logging model.
User Registration via Invitation Code
Admins can generate invitation codes via the invitation model.
Users register by visiting /register/<invite_code>/ and providing their username, password, and email.
Users created through this flow are synced with Jellyfin and can log in to both systems.
Error Handling
The application uses a custom LogEntry model to capture logs, including actions such as:

User login attempts
API request failures
User creation success or errors
Logs are viewable from the Django admin interface.

Contributing
Fork the repository.
Create a new feature branch (git checkout -b feature/new-feature).
Commit your changes (git commit -m 'Add new feature').
Push to the branch (git push origin feature/new-feature).
Create a Pull Request.
License
This project is licensed under the MIT License. See the LICENSE file for more details.

Notes:
Replace your-repo with the actual repository URL.
Adjust the Jellyfin setup instructions to match your exact setup process.