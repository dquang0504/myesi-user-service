FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
COPY alembic.ini ./alembic.ini
COPY alembic ./alembic

CMD uvicorn app.main:app --host 0.0.0.0 --port 8001 --workers 1 --reload