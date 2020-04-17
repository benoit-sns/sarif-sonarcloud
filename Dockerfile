FROM python:3.7-slim

COPY sarif /usr/bin/

WORKDIR /usr/bin

RUN pip install -r requirements.txt

ENTRYPOINT ["python3", "/usr/bin/main.py"]
