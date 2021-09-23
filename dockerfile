FROM python:slim
COPY . /opt
WORKDIR /opt
RUN python -m pip install -r requirements.txt
ENTRYPOINT ["python", "snotra.py"]