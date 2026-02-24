FROM python:3.11-slim

WORKDIR /app

# Install git (needed for some dependencies)
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Copy requirements first (better caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# These will be overridden by HF Secrets
ENV SHERLOCK_BOT_TOKEN=""
ENV ALLOWED_USER_IDS=""

# Run the bot
CMD ["python", "sherlock_project/__main__.py"]
