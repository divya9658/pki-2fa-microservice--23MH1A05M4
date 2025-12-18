# =========================
# Stage 1: Builder
# =========================
FROM python:3.11-slim AS builder

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt


# =========================
# Stage 2: Runtime
# =========================
FROM python:3.11-slim

ENV TZ=UTC
WORKDIR /app

# Install cron and timezone data
RUN apt-get update && \
    apt-get install -y cron tzdata && \
    rm -rf /var/lib/apt/lists/*

# Set timezone explicitly
RUN ln -sf /usr/share/zoneinfo/UTC /etc/localtime

# Copy installed Python packages from builder
COPY --from=builder /usr/local/lib/python3.11 /usr/local/lib/python3.11
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application files
COPY app ./app
COPY scripts ./scripts
COPY cron ./cron

# Copy keys
COPY student_private.pem .
COPY student_public.pem .
COPY instructor_public.pem .

# Create volume directories
RUN mkdir -p /data /cron && chmod 755 /data /cron

# Setup cron job
RUN chmod 0644 cron/2fa-cron && crontab cron/2fa-cron

EXPOSE 8080

# Start cron + API
CMD cron && uvicorn app.main:app --host 0.0.0.0 --port 8080
