export DOCKER_SCAN_SUGGEST := false
export DOCKER_BUILDKIT := 1

SHELL := /bin/bash
CONDA := conda run --no-capture-output -n aica
mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
mkfile_dir := $(dir $(mkfile_path))

check-env:
ifndef MODE
		$(error MODE is undefined)
endif

deps: environment.yml
		@conda env update -f environment.yml

black: $(shell find manager -type f -name *.py)
		@${CONDA} black -q manager/

lint: deps
		@${CONDA} black --check --diff -q manager/
		@${CONDA} flake8 manager/
		@MYPYPATH=manager ${CONDA} mypy --install-types --non-interactive manager/
		@find . -name "*.yml" | grep -v venv | xargs ${CONDA} yamllint
		@find . -name "*.sh" | xargs ${CONDA} bashlint

security: deps
		@${CONDA} bandit -q -ll -ii -r manager/
		@find . -name "requirements*.txt" | xargs printf -- '-r %s\n' | xargs ${CONDA} safety check

build: deps check-env lint security
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml build

test: check-env deps
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml run \
			-e SKIP_TASKS=true --rm manager /opt/venv/bin/python3 manage.py \
			test --noinput --failfast -v 3

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
		@find . -name ".py[co]" -delete
		@rm -rf aica_django/db.sqlite3
