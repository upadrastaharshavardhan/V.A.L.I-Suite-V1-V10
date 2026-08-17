FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /app/data /app/keys \
    && ssh-keygen -t rsa -b 2048 -f /app/keys/ssh_host_rsa_key -N "" -q \
    && ssh-keygen -t ed25519 -f /app/keys/ssh_host_ed25519_key -N "" -q
EXPOSE 2222
CMD ["python", "main.py"]
