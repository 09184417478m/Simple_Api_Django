# Use the official Python image as a base image
FROM python:3.9-slim

RUN apt-get update && apt-get install -y postgresql-client
RUN apt-get update && apt-get install -y gcc python3-dev libpq-dev netcat-openbsd
# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set work directory
WORKDIR /code

# Install dependencies
COPY requirements.txt /code/
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Copy project
COPY . /code/



# Add entrypoint script
COPY entrypoint.sh /code/

# Ensure the entrypoint script is executable
RUN chmod +x /code/entrypoint.sh

ENTRYPOINT ["/code/entrypoint.sh"]
