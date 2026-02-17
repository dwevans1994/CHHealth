FROM python:3.11-slim

RUN groupadd --system app && useradd --system --gid app app

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DJANGO_SETTINGS_MODULE=platform_service.settings

EXPOSE 8000

USER app

CMD ["gunicorn", "platform_service.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "4"]
