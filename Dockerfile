FROM python:3.12-slim

LABEL maintainer="OSINT EYE Team"
LABEL description="AI-Powered Attack Surface Intelligence Engine"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /root/.osint_eye/cache

VOLUME ["/app/output"]

ENTRYPOINT ["python", "osint_eye.py"]
CMD ["--help"]
