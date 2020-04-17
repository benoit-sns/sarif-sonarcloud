FROM python:3.7-slim

COPY sarif/ /usr/bin/sarif

WORKDIR /usr/bin

RUN pip install -r sarif/requirements.txt

ENTRYPOINT ["python3", "/usr/bin/sarif/main.py"]
