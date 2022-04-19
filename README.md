The intent of this project is to construct a functioning prototype of the AICA framework as outlined in Theron et al at
https://link.springer.com/content/pdf/10.1007%2F978-3-030-33432-1.pdf.

<h3>Building, Testing, and Sharing Changes</h3>

It is important to ensure your main branch is up to date before each working session, and you should commit your 
changes incrementally and often to ensure minimal divergence and chance of merge conflicts. Changes should be "intact" 
functionally (i.e., don't submit partially-completed work) and keep the main repository in a working state. This means 
you should think about functionality in the smallest possible chunks so you can keep your contributed work up to date.

Your host system will need to have a few things ready to go: Docker (installed from Docker itself, not your built-in 
distribution manager to ensure you get an up-to-date version), python3, python3-venv, build-essential (or the equivalent
or your platform; `make` should be sufficient but you may need other build tools depending on pip's wheel support in 
your environment), and if there is not a cryptography wheel available from `pip` for your operating system, you will 
also need libssl-dev, libffi-dev, and python-dev.

Set up and activate your venv, and then `make deps` to install required dependencies (or let your IDE handle that; 
PyCharm will detect the requirements file and prompt you). Note that when editing code inside of the Django project, 
PyCharm will not pay attention to its requirements.txt and will warn about missing dependencies. 

Before pushing your changes to a branch in GitLab, you should first locally execute a `make test` and ensure it 
completes successfully. If it does not, either fix the issues or propose exclusions to the relevant test areas 
(will be subject to peer review).

Once you have a passing build, you should commit your changes to a branch with a commit message that will be meaningful
to any reviewers of your code explaining (at a high level) what you changed and why. You can then push this branch up
to Gitlab.

Once the branch is in GitLab, you can wait for the pipeline (build) to complete successfully and then create a merge
request, or do so immediately. Either way your merge request will be blocked until the build passes and you have had a
maintainer approve your change.

<h3>Running</h3>

You will need to have Docker and Docker Compose installed on your system to run the AICA Django application. 

This code should be run via the Makefile entrypoint. You will need to specify whether you want to start this in
emulation mode or virtualized mode with the MODE environment variable (i.e., MODE should be either 
`emu` or `virt`). The virutalized mode is, however, only a stub and is meant for future expansion.
You can use export to set this for your session, or specific it before each `make` command (like `MODE=sim make build`).

When starting from scratch, run the following: `make build && make start`. Subsequently use `make stop` and `make start`
(or `make restart`) to stop/start the containers and `make build` to build them again (`make rebuild` is a handy alias
for stop/build/start). You can use `make clean` to clean up all container- and code-related files. 

Once you have started the agent, for demonstration purposes you can use the various `make <system>-shell` commands
(e.g., `make attacker-shell`) to open shells on various containers. You might wish, for example to start a shell on
the attacker and nmap the `target` host. 

You can view logs from the Dockerized containers with `make logs`. This will show all containers, so you might wish
to pipe this to `grep` to include/exclude containers by name as desired.

You can monitor the agent through several interfaces:

* http://localhost:8000 will be the Django app, as defined in `aica_django/`.
* http://localhost:5555 will be a Celery Flower instance, where you can monitor task execution
* http://localhost:15672 will be a RabbitMQ admin console, where you can monitor the task queue
* http://localhost:3000 will be a visualization of the emulated run, if you run it in `emu` mode. (login: admin/aica)

<h3>Code in this repository</h3>

The AICA agent is built as a Django project, and so the normal Django conventions are followed in the `aica_django/`
directory. Tests should be added to `aica_django/aica_django/tests` and use Django testing conventions.

Other top-level directories contain files for other containers in the emulated environment. They should contain at
least a `Dockerfile` and any files needed to be copied into the built container.

<h4>Other files and what they do</h4>

* `.gitignore` tells git which files to never check into the repository.
* `.gitlab-ci.yml` tells GitLab how to run the pipeline (test build) when a branch is created or updated.
* `docker-compose.yml`  is the YAML file instructing docker-compose how to create the necessary containers and networks for the agent
* `Makefile` is the primary entry point for this code. It should include test entrypoints as well as entrypoints. It is, in part, what executed by the GitLab pipeline via `.gitlab-ci.yml`.
* `requirements.txt` contains all external Python dependencies required for the dev environment (requirements for the running agent should be placed in `aica_django/requirements.txt`) 
* `setup.cfg` contains settings to control programs such as flake8. 
