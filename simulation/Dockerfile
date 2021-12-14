FROM python:3.8-slim-buster
WORKDIR /opt/cyst
COPY . /opt/cyst
RUN pip3 install -r requirements.txt
RUN chmod +x run_ncia_prototype.sh
EXPOSE 8080
CMD ["/bin/bash", "/opt/cyst/run_ncia_prototype.sh"]