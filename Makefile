export DOCKER_SCAN_SUGGEST := false
export DOCKER_BUILDKIT := 1

MAMBA_RUN := ${MAMBA_EXE} run -n aica-make

check-env:
ifndef MODE
		$(error MODE is undefined)
endif



init-core-env: security-precheck
		@${MAMBA_EXE} -y env create -f environment-core.yml
		@${MAMBA_RUN} python3 compute_dev.py

init-dev-envs:
		@${MAMBA_EXE} -y create -f attacker/environment.yml
		@${MAMBA_EXE} -y create -f honeypot/environment.yml
		@${MAMBA_EXE} -y create -f manager/environment.yml

security-precheck-init:
		@${MAMBA_EXE} -y create -f environment-security.yml
		@${MAMBA_EXE} run -n aica-secprecheck python3 compute_security.py

security-precheck-bandit:
		@${MAMBA_EXE} run -n aica-secprecheck bandit -q -ll -ii -r manager/

security-precheck-safety-core:
		@${MAMBA_EXE} run -n aica-secprecheck safety check -r reqs.txt --policy-file .safety-check-policy.yml
		@${MAMBA_EXE} run -n aica-secprecheck safety check -r reqsDev.txt --policy-file .safety-check-policy.yml

security-precheck-safety-attacker:
		@${MAMBA_EXE} run -n aica-secprecheck safety check -r attacker/reqs.txt --policy-file .safety-check-policy.yml
		@${MAMBA_EXE} run -n aica-secprecheck safety check -r attacker/reqsDev.txt --policy-file .safety-check-policy.yml

security-precheck-safety-honeypot:
		@${MAMBA_EXE} run -n aica-secprecheck safety check -r honeypot/reqs.txt --policy-file .safety-check-policy.yml
		@${MAMBA_EXE} run -n aica-secprecheck safety check -r honeypot/reqsDev.txt --policy-file .safety-check-policy.yml

security-precheck-safety-manager:
		@${MAMBA_EXE} run -n aica-secprecheck safety check -r manager/reqs.txt --policy-file .safety-check-policy.yml
		@${MAMBA_EXE} run -n aica-secprecheck safety check -r manager/reqsDev.txt --policy-file .safety-check-policy.yml

security-precheck: security-precheck-init security-precheck-bandit security-precheck-safety-core security-precheck-safety-attacker security-precheck-safety-honeypot security-precheck-safety-manager

		

security-dev-postcheck:
		@${MAMBA_EXE} list -n manager-dev --json | (${MAMBA_RUN} jake ddt -t CONDA_JSON)
		@${MAMBA_EXE} list -n honeypot-dev --json | (${MAMBA_RUN} jake ddt -t CONDA_JSON)
		@${MAMBA_EXE} list -n attacker-dev --json | (${MAMBA_RUN} jake ddt -t CONDA_JSON)

security-post-launch-check:
		@(docker exec honeypot micromamba list -n base --json) |  (${MAMBA_RUN} jake ddt -t CONDA_JSON)
		@(docker exec attacker /home/kali/bin/micromamba list -n base --json) |  (${MAMBA_RUN} jake ddt -t CONDA_JSON)
		@(docker exec manager /usr/src/app/bin/micromamba list -n base --json) |  (${MAMBA_RUN} jake ddt -t CONDA_JSON)

init: init-core-env init-dev-envs security-dev-postcheck



black:
		@${MAMBA_RUN} black -q manager/ attacker/

lint:
		@${MAMBA_RUN} yamllint .
		@${MAMBA_RUN} bashlint .
		@${MAMBA_RUN} black --check --diff -q manager/ attacker/
		@${MAMBA_RUN} mypy --install-types --warn-unreachable --strict --non-interactive --exclude test manager/




build: check-env
		@docker compose -f docker-compose.yml -f docker-compose-${MODE}.yml build 

tests: lint
		@MODE=emu docker compose -f docker-compose.yml -f docker-compose-emu.yml up --wait -d && \
			docker exec -e SKIP_TASKS=true \
			manager /bin/bash -c " \
				/usr/src/app/bin/micromamba run -n base coverage run --omit='*test*' manage.py test --noinput && \
				/usr/src/app/bin/micromamba run -n base coverage report --fail-under=30"

test: tests security-post-launch-check

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
