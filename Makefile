export DOCKER_SCAN_SUGGEST := false

SHELL := /bin/bash
VENV := venv
PYTHON := ${VENV}/bin/python3
FLAKE := ${VENV}/bin/flake8
BANDIT := ${VENV}/bin/bandit
BLACK := ${VENV}/bin/black
SAFETY := ${VENV}/bin/safety
BASHLINT := ${VENV}/bin/bashlint
YAMLLINT := ${VENV}/bin/yamllint
ACTIVATE := ${VENV}/bin/activate
mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
mkfile_dir := $(dir $(mkfile_path))

check-env:
ifndef MODE
		$(error MODE is undefined)
endif

${ACTIVATE}: requirements.txt
		@test -d ${VENV}/bin || python3 -m venv ${VENV}
venv: ${ACTIVATE}

deps: venv
		@${PYTHON} -m pip install -qU pip wheel
		@${PYTHON} -m pip install -qUr requirements.txt

lint: deps
		@find . -name "*.yml" | grep -v venv | xargs ${YAMLLINT}
		@${BLACK} -q manager/
		@${FLAKE} manager/
		@find . -name "*.sh" | xargs ${BASHLINT}

security: deps
		@${BANDIT} -q -ll -ii -r manager/
		@find . -name "requirements*.txt" | xargs printf -- '-r %s\n' | xargs ${SAFETY} check --bare

build: check-env lint security
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml build

test: build
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml run \
			-e SKIP_TASKS=true --rm manager /opt/venv/bin/python3 manage.py \
			test --noinput --failfast -v 3

start: build
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml up -d

stop: check-env
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml down -v

rebuild: stop build start

restart: stop start

attacker-shell: check-env
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml exec -u root attacker /bin/bash

target-shell: check-env
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml exec -u root target /bin/bash

manager-shell: check-env
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml exec -u root manager /bin/bash

logs: check-env
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml logs -f

clean: check-env
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml down -v --rmi all --remove-orphans
		@find . -name ".py[co]" -delete
		@rm -rf aica_django/db.sqlite3
