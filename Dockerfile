# Use an official Python image as the base
FROM python:3.11-slim

# Set the working directory inside the container
WORKDIR /app

# Install system dependencies (needed for psycopg2)
RUN apt-get update && apt-get install -y \
    gcc libpq-dev && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies first (Docker cache optimisation)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Cloud Run sets PORT environment variable - gunicorn listens on it
ENV PORT=8080

# Use gunicorn (production-grade WSGI server) instead of Flask dev server
CMD exec gunicorn --bind :$PORT --workers 2 --threads 4 run:app

