import re
import subprocess

from celery import current_app
from celery.app import shared_task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)

nginx_regex = (
    r"(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - "
    r"\[(?P<dateandtime>\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} "
    r"(\+|\-)\d{4})\] ((\"(?P<method>(GET|POST)) )(?P<url>.+)"
    r"(HTTP\/1\.1\")) (?P<statuscode>\d{3}) (?P<bytes_sent>\d+) "
    r"(\"(?P<referer>(\-)|(.+))\") (\"(?P<useragent>[^\"]+)\")"
)


@shared_task(name="poll-nginx-accesslogs")
def poll_nginx_accesslogs():
    logger.info(f"Running {__name__}: poll_nginx_accesslogs")
    matcher = re.compile(nginx_regex)

    file_path = "/var/log/nginx/access.log"
    f = subprocess.Popen(
        ["tail", "-F", file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    while True:
        line = f.stdout.readline().decode("utf-8").rstrip()
        log_dict = matcher.match(line)
        if log_dict:
            current_app.send_task(
                "ma-knowledge_base-record_nginx_accesslog",
                [log_dict.groupdict()],
            )
        else:
            logger.warning(f"Unknown format in Nginx log: <{line}>")
