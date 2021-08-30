#!/bin/bash

cd /usr/src/app

echo "Starting Celery workers and gunicorn"
service supervisor start

# Tell Celery to not run tasks on the following manage.py invocations
export SKIP_TASKS=true

# Apply database migrations
echo "Creating Django Database"
/opt/venv/bin/python3 manage.py sqlcreate -D \
  | grep -v USER \
  | /opt/venv/bin/python3 manage.py dbshell --database postgres
/opt/venv/bin/python3 manage.py migrate

# Create superuser for Django
if [ "$DJANGO_SUPERUSER_USERNAME" ]; then
    echo "Creating Django Superuser"
    /opt/venv/bin/python3 manage.py createsuperuser --noinput
fi

echo "Manager started"

tail -f /dev/null