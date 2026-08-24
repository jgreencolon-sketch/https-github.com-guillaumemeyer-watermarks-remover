FROM python:3.12-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8765

WORKDIR /service

RUN addgroup -S cleaner && adduser -S -G cleaner cleaner

COPY app ./app

USER cleaner

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import json,urllib.request; assert json.load(urllib.request.urlopen('http://127.0.0.1:8765/health', timeout=2))['ok']"

CMD ["python", "-m", "app.server"]
