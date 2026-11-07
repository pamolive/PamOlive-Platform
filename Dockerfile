FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN useradd --create-home --shell /usr/sbin/nologin pamolive
COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock
COPY . .
RUN python manage.py collectstatic --noinput
USER pamolive
EXPOSE 8000
HEALTHCHECK --interval=20s --timeout=5s --start-period=20s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health/', timeout=4)"
CMD ["python", "deploy/runtime.py"]
