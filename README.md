The intent of this project is to build on the ideas of the AICA framework as outlined in Theron et al at https://link.springer.com/content/pdf/10.1007%2F978-3-030-33432-1.pdf. This project will work towards a fully-functional agent with increasingly advanced capabilities that can be used in both research and production contexts.

<h3>Building, Testing, and Sharing Changes</h3>

It is important to ensure your main branch is up-to-date before each working session, and you should commit your changes incrementally and often to ensure minimal divergence and chance of merge conflicts. Changes should be "intact" functionally (i.e., don't submit partially-completed work) and keep the main repository in a working state. This means you should think about functionality in the smallest possible chunks to keep your contributed work up to date.

Your host system will need to have a few things: Docker (installed from Docker itself, not your built-in distribution manager to ensure you get an up-to-date version), Docker Compose (installed with Docker in Windows, MacOS but needs to be separately installed in Linux), python3, python3-venv, build-essential (or the equivalent or your platform; `make` should be sufficient but you may need other build tools depending on pip's wheel support in your environment), and if there is not a cryptography wheel available from `pip` for your operating system, you will also need libssl-dev, libffi-dev, and python-dev. See full requirements for building each Docker container in the respective `requirements.txt` files (the `requirements.txt` at the root is for development/test purposes).

You can bootstrap your environment with `make deps`, which will call `make venv`. Note that this will use the `venv/` path in your project directly, which might overlap/conflict with your IDE.

Changes must be pushed to a branch and PR'ed to main. Before pushing your changes, you should first locally execute a `make test` and ensure it completes successfully. If it does not, either fix the issues or propose exclusions to the relevant test areas (will be subject to peer review).

Once you have a passing build, you should commit your changes to a branch with a commit message that will be meaningful to any reviewers of your code explaining (at a high level) what you changed and why. You can then push the branch and make a PR.

<h3>Running</h3>

This code should be run via the Makefile entrypoint. You will need to specify whether you want to start this in emulation mode or virtualized mode with the MODE environment variable (i.e., MODE should be either `emu` or `virt`). The virutalized mode is, however, only a stub and is meant for future expansion. You can use export to set this for your session, or specific it before each `make` command (like `MODE=emu make build`).

When starting from scratch, run the following: `make build && make start`. Subsequently use `make stop` and `make start` (or `make restart`) to stop/start the containers and `make build` to build them again (`make rebuild` is a handy alias for stop/build/start). You can use `make clean` to clean up all container- and code-related files. 

Once you have started the agent, for demonstration purposes you can use the various `make <system>-shell` commands (e.g., `make attacker-shell`) to open shells on various containers. You might wish, for example to start a shell on the attacker and nmap the `target` host. 

You can view logs from the Dockerized containers with `make logs`. This will show all containers, so you might wish to pipe this to `grep`/`egrep` to include/exclude containers by name as desired. For example: `make logs | egrep ^(manager|manager_graphdb)`.

You can monitor the agent through several interfaces:

* [http://localhost:3000](): Grafana console 
* [http://localhost:5555](): Celery Flower instance, where you can monitor task execution
* [http://localhost:7474](): Neo4j web interface
* [http://localhost:8000](): Django app, as defined in `aica_django/`.
* [http://localhost:15672](): RabbitMQ admin console, where you can monitor the task queue

<h3>Code in this repository</h3>

The AICA agent is built as a Django project, and so the normal Django conventions are followed in the `manager/` directory. Tests should be added to `manager/aica_django/tests` and use Django testing conventions. Other top-level directories contain files for other containers in the emulated environment. They should contain at least a `Dockerfile` and any files needed to be copied into the built container.

<h4>Other files and what they do</h4>

* `Makefile` is the primary entry point for this code. It should include test entrypoints as well as entrypoints.
* `.dockerignore` tells Docker what <em>not</em> to copy into container contexts
* `.gitignore` tells git which files to never check into the repository.
* `.yamllint` configures the YAML lint that runs at build/test time
* `docker-compose.yml`  is the YAML file instructing docker-compose how to create the necessary containers and networks for the agent. The additional `docker-compose-emu.yml` and `docker-compose-virt.yml` have addition definitions intended for those modes only and are additionally invoked in the `Makefile` based on the MODE environmental variable.
* `requirements.txt` contains all external Python dependencies required for the dev environment.
* `setup.cfg` contains settings to control programs such as flake8. 

<h4>Maintainers</h4>

Currently the primary/sole maintainer for this project is [mailto:bblakely@anl.gov](Benjamin Blakely), a cybersecurity and machine learning researcher at Argonne National Laboratory.