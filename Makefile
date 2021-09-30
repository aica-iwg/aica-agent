SHELL := /bin/bash
BUILD_DIR := build
VENV := $(BUILD_DIR)/venv
PIP := ${VENV}/bin/pip
FLAKE := ${VENV}/bin/flake8
BANDIT := ${VENV}/bin/bandit
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

deps: requirements.txt venv
		@${PIP} install -qU pip wheel
		@${PIP} install -qUr requirements.txt

build: deps aica_django/Dockerfile attacker/Dockerfile target/Dockerfile ids/Dockerfile honeypot/Dockerfile check-env
		@docker-compose -f docker-compose.yml -f docker-compose-${MODE}.yml build

test: build
		@find . -name "*.yml" -exec ${YAMLLINT} {} \;
		@find . -name "*.sh" -exec ${BASHLINT} {} \;
		@find aica_django/ -name "*.py" -exec ${FLAKE} {} \;
		@${BANDIT} -q -ll -ii -r aica_django/
		@${SAFETY} check -r aica_django/requirements.txt --bare
		@${SAFETY} check -r honeypot/requirements.txt --bare
		@docker-compose run -e SKIP_TASKS=true --rm manager \
		    /opt/venv/bin/python3 manage.py test --noinput --failfast -v 3

start: build
		@docker-compose -f docker-compose.yml -f docker-compose-${MODE}.yml up -d

stop: check-env
		@docker-compose -f docker-compose.yml -f docker-compose-${MODE}.yml down -v

rebuild: stop build start

restart: stop start

attacker-shell:
		@docker-compose exec -u root attacker /bin/bash

target-shell:
		@docker-compose exec -u root target /bin/bash

manager-shell:
		@docker-compose exec -u root manager /bin/bash

logs:
		@docker-compose logs -f

clean: check-env
		@docker-compose -f docker-compose.yml -f docker-compose-${MODE}.yml down -v --rmi all --remove-orphans
		@find . -name ".py[co]" -delete
		@rm -rf aica_django/db.sqlite3
		@rm -rf $(BUILD_DIR)
