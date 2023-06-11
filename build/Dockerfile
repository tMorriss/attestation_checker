FROM python:latest

COPY ./ /attestation_checker
WORKDIR /attestation_checker

RUN pip3 install --upgrade pip
RUN pip3 install -r ./build/requirements.txt

ENV FLASK_APP=index.py
CMD ["/usr/local/bin/flask" "run" "--host=0.0.0.0" "--port=8010"]
