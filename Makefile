export DOCKER_SCAN_SUGGEST := false
export DOCKER_BUILDKIT := 1

MAMBA_RUN := ${MAMBA_EXE} run -n aica-make

check-env:
ifndef MODE
		$(error MODE is undefined)
endif


init-core-env:
		@${MAMBA_EXE} -y env create -f environment-core.yml
		@${MAMBA_RUN} python3 compute_dev.py

init-dev-envs:
		@${MAMBA_EXE} -y env create -f attacker/environment.yml
		@${MAMBA_EXE} -y env create -f honeypot/environment.yml
		@${MAMBA_EXE} -y env create -f manager/environment.yml

security-precheck-init:
		@${MAMBA_EXE} -y env create -f environment-security.yml
		@${MAMBA_EXE} run -n aica-secprecheck python3 compute_security.py

security-precheck-bandit:
		@${MAMBA_EXE} run -n aica-secprecheck bandit -q -ll -ii -r manager/

security-precheck-safety-core:
		@${MAMBA_EXE} run -n aica-secprecheck safety check -r reqs.txt

security-precheck-safety-attacker:
		@${MAMBA_EXE} run -n aica-secprecheck safety check -r attacker/reqs.txt

security-precheck-safety-honeypot:
		@${MAMBA_EXE} run -n aica-secprecheck safety check -r honeypot/reqs.txt

security-precheck-safety-manager:
		@${MAMBA_EXE} run -n aica-secprecheck safety check -r manager/reqs.txt

security-precheck: security-precheck-init security-precheck-bandit security-precheck-safety-core security-precheck-safety-attacker security-precheck-safety-honeypot security-precheck-safety-manager

		

security-postcheck:
		@${MAMBA_EXE} list -n manager-dev --json | (${MAMBA_RUN} jake ddt -t CONDA_JSON)
		@${MAMBA_EXE} list -n honeypot-dev --json | (${MAMBA_RUN} jake ddt -t CONDA_JSON)
		@${MAMBA_EXE} list -n attacker-dev --json | (${MAMBA_RUN} jake ddt -t CONDA_JSON)


init: security-precheck init-core-env init-dev-envs security-postcheck
		


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
