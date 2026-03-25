FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY nightowl/ nightowl/
COPY configs/ configs/
COPY plugins/ plugins/
COPY wordlists/ wordlists/

RUN pip install --no-cache-dir -e ".[full]"

EXPOSE 8080

CMD ["nightowl", "dashboard", "--host", "0.0.0.0", "--port", "8080"]
