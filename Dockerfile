# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DJANGO_SETTINGS_MODULE=jellyfin_project.settings \
    PORT=8056

# Create a non-root user
RUN useradd -m -s /bin/bash app_user

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Change ownership of the app directory to app_user
RUN chown -R app_user:app_user /app

# Switch to non-root user
USER app_user


# Expose port

# Start Gunicorn
CMD ["sh", "-c", "python manage.py migrate && gunicorn jellyfin_project.wsgi:application --bind 0.0.0.0:$PORT --workers 3 --timeout 120"]
