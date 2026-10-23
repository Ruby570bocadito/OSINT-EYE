FROM python:3.12-slim

# Versión de la imagen: por defecto la de core/__init__.py; el workflow de
# release la pasa con --build-arg VERSION=$(grep core/__init__.py) para que
# nunca diverja del paquete (tarea version-unica).
ARG VERSION=2.1.1

LABEL maintainer="OSINT EYE Team"
LABEL description="AI-Powered Attack Surface Intelligence Engine"
LABEL version="${VERSION}"

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    whois \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Non-root runtime user; cache and output live in writable locations
RUN useradd --create-home --shell /bin/bash osint \
    && mkdir -p /home/osint/.osint_eye/cache /app/output \
    && chown -R osint:osint /app /home/osint/.osint_eye

USER osint

ENV HOME=/home/osint

VOLUME ["/app/output"]

ENTRYPOINT ["python", "osint_eye.py"]
CMD ["--help"]
