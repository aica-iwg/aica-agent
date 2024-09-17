export DOCKER_SCAN_SUGGEST := false
export DOCKER_BUILDKIT := 1

MAMBA_RUN := ${MAMBA_EXE} run -n aica-make

init-core-env:
		@${MAMBA_EXE} create -f environment-core.yml -y
		@${MAMBA_RUN} python3 compute_dev.py

init-dev-envs:
<<<<<<< HEAD
		@${MAMBA_EXE} create -f attacker/environment.yml -y
		@${MAMBA_EXE} create -f honeypot/environment.yml -y
		@${MAMBA_EXE} create -f manager/environment.yml -y   
=======
		@${MAMBA_EXE} create -f manager/environment.yml -y
>>>>>>> main

security-precheck-init:
		@${MAMBA_EXE} create -f environment-security.yml -y
		@${MAMBA_EXE} run -n aica-secprecheck python3 compute_security.py

security-precheck-bandit:
		@${MAMBA_EXE} run -n aica-secprecheck bandit -q -ll -ii -r manager/

security-precheck-safety-core:
		@${MAMBA_EXE} run -n aica-secprecheck safety check -r reqs.txt --policy-file .safety-check-policy.yml
		@${MAMBA_EXE} run -n aica-secprecheck safety check -r reqsDev.txt --policy-file .safety-check-policy.yml

security-precheck-safety-manager:
		@${MAMBA_EXE} run -n aica-secprecheck safety check -r manager/reqs.txt --policy-file .safety-check-policy.yml
		@${MAMBA_EXE} run -n aica-secprecheck safety check -r manager/reqsDev.txt --policy-file .safety-check-policy.yml

security-precheck: security-precheck-init security-precheck-bandit security-precheck-safety-core security-precheck-safety-manager
		

security-post-launch-check:
		@(docker exec manager /usr/src/app/bin/micromamba list -n base --json) |  (${MAMBA_RUN} jake ddt -t CONDA_JSON)

init: init-core-env init-dev-envs

black:
		@${MAMBA_RUN} black -q manager/

lint:
		@${MAMBA_RUN} yamllint .
		@${MAMBA_RUN} bashlint .
		@${MAMBA_RUN} black --check --diff -q manager/
		@${MAMBA_RUN} mypy --install-types --warn-unreachable --strict --non-interactive --exclude test manager/

build:
		@docker compose build 

tests:
		@docker compose up --wait -d && \
			docker exec -e SKIP_TASKS=true \
			manager /bin/bash -c " \
				/usr/src/app/bin/micromamba run -n base coverage run --omit='*test*' manage.py test --noinput && \
				/usr/src/app/bin/micromamba run -n base coverage report --fail-under=30"

test: tests security-post-launch-check

start:
		@docker compose up --wait -d

stop:
		@docker compose down --remove-orphans

stop_purge:
		@docker compose down --remove-orphans -v

rebuild: build stop start

rebuild_purge: build stop_purge start

restart: stop start

logs:
		@docker compose logs -f

clean:
		@docker compose down -v --rmi all --remove-orphans
