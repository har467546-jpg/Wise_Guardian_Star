FROM docker:27-cli

RUN apk add --no-cache python3

WORKDIR /app

COPY app.py /app/app.py

ENV PYTHONUNBUFFERED=1

CMD ["python3", "/app/app.py"]
