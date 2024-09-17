#!/bin/bash
set -e

cd /usr/src/app

echo "Starting Celery workers and gunicorn"
cat <<EOF > /etc/supervisor/conf.d/0_env.conf
[supervisord]
environment=
  CELERY_HOST="${CELERY_HOST}",
  CELERY_PORT="${CELERY_PORT}",
  CELERY_USER="${CELERY_USER}",
  CELERY_PASSWORD="${CELERY_PASSWORD}",
  MONGO_SERVER="${MONGO_SERVER}",
  MONGO_SERVER_PORT="${MONGO_SERVER_PORT}",
  MONGO_INITDB_DATABASE="${MONGO_INITDB_DATABASE}",
  MONGO_INITDB_USER="${MONGO_INITDB_USER}",
  MONGO_INITDB_PASS="${MONGO_INITDB_PASS}",
  TAP_IF="${TAP_IF}",
  HOME_NET="${HOME_NET}"
EOF

/usr/bin/supervisord -c /etc/supervisor/supervisord.conf

# Tell Celery to not run tasks on the following manage.py invocations
export SKIP_TASKS=true

# Apply database migrations
echo "Creating Django Database"
python3 manage.py sqlcreate -D \
  | grep -v USER \
  | python3 manage.py dbshell --database postgres

python3 manage.py makemigrations && python3 manage.py migrate

# Create superuser for Django
if [ "$DJANGO_SUPERUSER_USERNAME" ]; then
    echo "Creating Django Superuser"
    python3 manage.py createsuperuser --noinput
fi

echo "Manager started"

tail -f /dev/null