#!/bin/bash

cd /usr/src/app || exit 1

echo "Starting Celery workers and gunicorn"
cat <<EOF > /etc/supervisor/conf.d/0_env.conf
[supervisord]
environment=
  MODE="${MODE}",
  MONGO_SERVER="${MONGO_SERVER}",
  MONGO_SERVER_PORT="${MONGO_SERVER_PORT}",
  MONGO_INITDB_DATABASE="${MONGO_INITDB_DATABASE}",
  MONGO_INITDB_USER="${MONGO_INITDB_USER}",
  MONGO_INITDB_PASS="${MONGO_INITDB_PASS}"
EOF

service supervisor start

# Tell Celery to not run tasks on the following manage.py invocations
export SKIP_TASKS=true

# Apply database migrations
echo "Creating Django Database"
/opt/venv/bin/python3 manage.py sqlcreate -D \
  | grep -v USER \
  | /opt/venv/bin/python3 manage.py dbshell --database postgres

/opt/venv/bin/python3 manage.py makemigrations && /opt/venv/bin/python3 manage.py migrate

# Create superuser for Django
if [ "$DJANGO_SUPERUSER_USERNAME" ]; then
    echo "Creating Django Superuser"
    /opt/venv/bin/python3 manage.py createsuperuser --noinput
fi

# Start netflow exporter (configured in /etc/default/fprobe, copied to container)
service fprobe start

echo "Manager started in mode: ${MODE}"

tail -f /dev/null