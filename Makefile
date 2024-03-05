export DOCKER_SCAN_SUGGEST := false
export DOCKER_BUILDKIT := 1

CONDA := conda run --no-capture-output -n aica

check-env:
ifndef MODE
		$(error MODE is undefined)

endif

init: environment.yml
		@conda env update -f environment.yml

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

start: build
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml up --wait -d

stop: check-env
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml down 

stop_purge: check-env
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml down -v

rebuild: build stop start

restart: stop start

web_attack: check-env
		@docker compose -f docker-compose.yml -f docker-compose-emu.yml exec target /bin/bash -c "ipset add allowlist attacker"
		@docker compose -f docker-compose.yml -f docker-compose-emu.yml exec attacker /bin/bash -c "source attacker/bin/activate && python -m unittest discover -s /root/tests -p 'test_*.py'"
		@docker compose -f docker-compose.yml -f docker-compose-emu.yml exec target /bin/bash -c "ipset del allowlist attacker"

logs: check-env
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml logs -f

clean: check-env
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml down -v --rmi all --remove-orphans
