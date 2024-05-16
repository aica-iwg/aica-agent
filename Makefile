export DOCKER_SCAN_SUGGEST := false
export DOCKER_BUILDKIT := 1

MAMBA_RUN := @${MAMBA_EXE} run -n aica-make

check-env:
ifndef MODE
		$(error MODE is undefined)
endif


init-core-env:
		@${MAMBA_EXE} env create -f environment-core.yml
		@${MAMBA_RUN} python3 compute_dev.py

init-dev-envs:
		@${MAMBA_EXE} env create -f attacker/environment.yml
		@${MAMBA_EXE} env create -f honeypot/environment.yml
		@${MAMBA_EXE} env create -f manager/environment.yml

security-precheck:
		@${MAMBA_RUN} bandit -q -ll -ii -r manager/
		@${MAMBA_RUN} safety check -r manager/environment-manager.yml
		@${MAMBA_RUN} safety check -r honeypot/environment-honeypot.yml
		@${MAMBA_RUN} safety check -r attacker/environment-attacker.yml

security-postcheck:
		@${MAMBA_EXE} list -n manager-dev --json | (/home/iprieto/.local/bin/micromamba run -n aica-make jake ddt -t CONDA_JSON)
		@${MAMBA_EXE} list -n honeypot-dev --json | (/home/iprieto/.local/bin/micromamba run -n aica-make jake ddt -t CONDA_JSON)
		@${MAMBA_EXE} list -n attacker-dev --json | (/home/iprieto/.local/bin/micromamba run -n aica-make jake ddt -t CONDA_JSON)


init: init-core-env security-precheck init-dev-envs security-postcheck
		


black:
		@${MAMBA_RUN} black -q manager/ attacker/

lint:
		@${MAMBA_RUN} yamllint .
		@${MAMBA_RUN} bashlint .
		@${MAMBA_RUN} black --check --diff -q manager/ attacker/
		@${MAMBA_RUN} mypy --install-types --warn-unreachable --strict --non-interactive --exclude test manager/




build: check-env
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml build 

tests:
		@MODE=emu docker compose -f docker-compose.yml -f docker-compose-emu.yml up --wait -d && \
			docker exec -e SKIP_TASKS=true \
			manager /bin/bash -c " \
				/usr/src/app/bin/micromamba run -n base coverage run --omit='*test*' manage.py test --noinput && \
				/usr/src/app/bin/micromamba run -n base coverage report --fail-under=30"

test-initless: lint security-precheck security-postcheck tests


test: lint tests


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
