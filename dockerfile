FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && gunicorn --version

COPY . .

EXPOSE 3000

CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:3000", "--workers", "2"]
