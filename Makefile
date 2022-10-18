export DOCKER_SCAN_SUGGEST := false
export DOCKER_BUILDKIT := 1

CONDA := conda run --no-capture-output -n aica

check-env:
ifndef MODE
		$(error MODE is undefined)
endif

deps: environment.yml
		@conda env update -f environment.yml

black:
		@${CONDA} black -q manager/

lint:
		@${CONDA} black --check --diff -q manager/
		@MYPYPATH=manager ${CONDA} mypy --install-types --non-interactive manager/
		@${CONDA} yamllint .
		@${CONDA} bashlint .

security:
		@${CONDA} bandit -q -ll -ii -r manager/
		@${CONDA} safety check -r manager/requirements.txt
		@${CONDA} safety check -r honeypot/requirements.txt

build: check-env
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml build

test: check-env lint security
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml \
			run -e SKIP_TASKS=true --rm -v TESTDIR:/tmp/testdir \
			manager /opt/venv/bin/coverage run --data-file=/tmp/testdir/.coverage --omit="*test*" \
				manage.py test --noinput --failfast -v 3
		# Starting with a low threshold as we increase our test coverage
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml \
			run -e SKIP_TASKS=true --rm -v TESTDIR:/tmp/testdir \
			manager /opt/venv/bin/coverage report --data-file=/tmp/testdir/.coverage --fail-under=30

start: build
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml up -d

stop: check-env
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml down -v

rebuild: stop build start

mrebuild:
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml up -d --no-deps --build manager

restart: stop start

manager-shell: check-env
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml exec -u root manager /bin/bash

attacker-shell: check-env
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml exec -u root attacker /bin/bash

target-shell: check-env
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml exec -u root target /bin/bash

logs: check-env
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml logs -f

mlogs: check-env
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml logs -f | grep "^manager\b"

clean: check-env
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml down -v --rmi all --remove-orphans
