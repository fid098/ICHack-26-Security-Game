FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app app

RUN useradd --create-home appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# The Hacktron CLI is not installed in this image. With HACKTRON_CMD unset the
# scanner degrades to a "not configured" note per snippet and the game remains
# fully playable, so the stack is runnable without it.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
