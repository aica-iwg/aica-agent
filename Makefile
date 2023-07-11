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
		@${CONDA} yamllint .
		@${CONDA} bashlint .
		@${CONDA} pylint -E --disable=all --enable=missing-docstring --ignore-patterns=__init__.py,test manager
		@${CONDA} black --check --diff -q manager/
		@MYPYPATH=manager ${CONDA} mypy --install-types --warn-unreachable --strict --non-interactive --exclude test manager/

security:
		@${CONDA} bandit -q -ll -ii -r manager/
		@${CONDA} safety check -r manager/requirements.txt
		@${CONDA} safety check -r honeypot/requirements.txt

build: check-env
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml build

test: check-env lint security
		@MODE=emu docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml \
			run -e SKIP_TASKS=true --rm \
			manager /bin/bash -c " \
				/opt/venv/bin/coverage run --omit='*test*' manage.py test --noinput && \
				/opt/venv/bin/coverage report --fail-under=30"

start: build
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml up --wait -d

stop: check-env
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml down -v

rebuild: build stop start

restart: stop start

retest: stop build test

logs: check-env
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml logs -f

clean: check-env
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml down -v --rmi all --remove-orphans
