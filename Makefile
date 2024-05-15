export DOCKER_SCAN_SUGGEST := false
export DOCKER_BUILDKIT := 1

CONDA_IMPL := /home/iprieto/.local/bin/micromamba
CONDA := @${CONDA_IMPL} run --no-capture-output -n aica

check-env:
ifndef MODE
		$(error MODE is undefined)
endif


dev-init:
		@${CONDA_IMPL} create -n aica-bootstrap-env
		@${CONDA_IMPL} install -y -n aica-bootstrap-env pyyaml packaging
		@${CONDA_IMPL} run -n aica-bootstrap-env python3 compute_dev.py


		@${CONDA_IMPL} env create -f attacker/environment.yml
		@${CONDA_IMPL} env create -f honeypot/environment.yml
		@${CONDA_IMPL} env create -f manager/environment.yml
		


init: environment-core.yml
		@${CONDA_IMPL} env create -f environment-core.yml

black:
		@${CONDA} black -q manager/ attacker/

lint:
		@${CONDA} yamllint .
		@${CONDA} bashlint .
		@${CONDA} black --check --diff -q manager/ attacker/
		@MYPYPATH=manager ${CONDA} mypy --install-types --warn-unreachable --strict --non-interactive --exclude test manager/

security:
		@${CONDA} bandit -q -ll -ii -r manager/
		@${CONDA} safety check -r manager/requirements.txt
		@${CONDA} safety check -r honeypot/requirements.txt

build: check-env
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml build 

test: lint security
		@MODE=emu docker compose -f docker-compose.yml -f docker-compose-emu.yml \
			run -e SKIP_TASKS=true --rm \
			manager /bin/bash -c " \
				/opt/venv/bin/coverage run --omit='*test*' manage.py test --noinput && \
				/opt/venv/bin/coverage report --fail-under=30"

start: check-env 
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml up --wait -d

stop: check-env
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml down --remove-orphans

stop_purge: check-env
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml down --remove-orphans -v

rebuild: build stop start

rebuild_purge: build stop_purge start

restart: stop start

# Not currently working, but want to fix in the future
# web_attack: check-env
# 		@docker compose -f docker-compose.yml -f docker-compose-emu.yml exec target /bin/bash -c "ipset add allowlist attacker"
# 		@docker compose -f docker-compose.yml -f docker-compose-emu.yml exec attacker /bin/bash -c "source ./attacker/bin/activate && python -m unittest discover -s ./tests/ -p 'test_*.py'"
# 		@docker compose -f docker-compose.yml -f docker-compose-emu.yml exec target /bin/bash -c "ipset del allowlist attacker"

logs: check-env
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml logs -f

clean: check-env
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml down -v --rmi all --remove-orphans
