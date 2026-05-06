FROM python:3.12-slim AS base

# Prevent Python from writing pyc files
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies and security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    git \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install ProjectDiscovery tools
RUN mkdir -p /opt/tools && \
    # Subfinder
    wget -q "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip" -O /tmp/subfinder.zip && \
    unzip -q /tmp/subfinder.zip -d /opt/tools/ && \
    mv /opt/tools/subfinder /usr/local/bin/ && \
    # httpx
    wget -q "https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip" -O /tmp/httpx.zip && \
    unzip -q /tmp/httpx.zip -d /opt/tools/ && \
    mv /opt/tools/httpx /usr/local/bin/ && \
    # naabu
    wget -q "https://github.com/projectdiscovery/naabu/releases/download/v2.2.0/naabu_2.2.0_linux_amd64.zip" -O /tmp/naabu.zip && \
    unzip -q /tmp/naabu.zip -d /opt/tools/ && \
    mv /opt/tools/naabu /usr/local/bin/ && \
    # nuclei
    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.8/nuclei_3.3.8_linux_amd64.zip" -O /tmp/nuclei.zip && \
    unzip -q /tmp/nuclei.zip -d /opt/tools/ && \
    mv /opt/tools/nuclei /usr/local/bin/ && \
    # Cleanup
    rm -rf /tmp/*.zip /opt/tools && \
    # Set capabilities for naabu (raw socket access)
    setcap cap_net_raw=+ep /usr/local/bin/naabu || true

# Set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create data directories
RUN mkdir -p /tmp/foxrecon_data/{screenshots,scan_results,reports}

# Default command
CMD ["python", "-m", "main"]
