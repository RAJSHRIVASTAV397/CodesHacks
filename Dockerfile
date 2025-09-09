FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
COPY requirements-dev.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt -r requirements-dev.txt

# Copy the rest of the application
COPY . .

# Create non-root user
RUN useradd -m codeshacks && \
    chown -R codeshacks:codeshacks /app

USER codeshacks

ENTRYPOINT ["python", "codeshacks.py"]
