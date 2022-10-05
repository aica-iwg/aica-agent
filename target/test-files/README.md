# Notes

In order to be able to generate logs more interesting than 10 different [Eicar test file](https://www.eicar.org/download-anti-malware-testfile/) alerts, some of the testing has made use of real, live malware that is registered in ClamAV's signature database. However, these samples have not and will not be pushed to this repository for reasons that should be obvious.

The files that should be in this directory are as follows:

```
.
├── avtest.sh
├── eicar.com
├── malware.zip
└── README.md
```

- `avtest.sh` is a shell script that can be run inside the target docker container to automate the process of generating log data which is then entered into the knowledge graph under neo4j (see manager files)
- `eicar.com` is a plain eicar test file that gets copied into the target docker container which can then be used for additional testing. The current configuration doesn't check files owned by root, so you'll need to change ownership to the `appuser` user (as root, `chown appuser:appuser eicar.com`)
- `malware.zip` is a password protected zip containing a single eicar test file and **zero malicious programs**, and is opened automatically by the `avtest.sh` script. In the event that you want to use live malware samples to generate more diverse logs, you can create a new zipped folder with your samples. **No party associated with this repository and project is liable for any accidental/intentional detonation of malware. Practice safe malware handling procedures at all times if you are getting your own samples.**. Password is `infected`.
