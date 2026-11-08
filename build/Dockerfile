FROM python:3.12

COPY ./ /attestation_checker
WORKDIR /attestation_checker

RUN pip3 install --upgrade pip
RUN pip3 install -r ./build/requirements.txt

ENV FLASK_APP=index.py
CMD ["gunicorn", "--bind=0.0.0.0:8080", "--workers=2", "--access-logfile=-", "--error-logfile=-", "index:app"]
