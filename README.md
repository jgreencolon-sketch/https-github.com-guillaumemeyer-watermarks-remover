# Remove AI Marks Service

A small Dockerized HTTP service for inspecting and removing container metadata
from user-owned PNG, JPEG, and WebP files.

The service removes C2PA/JUMBF container records, EXIF, XMP, comments, and other
known non-rendering metadata without decoding or re-encoding image pixels.

## Important limits

This service does **not** remove or verify pixel-domain SynthID-class signals,
C2PA soft binding, secret vendor detectors, model backdoors, audio watermarks,
or video watermarks. Metadata cleaning is privacy and provenance hygiene. It is
not proof that media was created by a human.

## Run with Docker

```bash
docker pull ghcr.io/jgreencolon-sketch/remove-ai-marks-service:latest
docker run --rm -p 8765:8765 \
  ghcr.io/jgreencolon-sketch/remove-ai-marks-service:latest
```

Optional API authentication:

```bash
docker run --rm -p 8765:8765 \
  -e WATERMARKS_SERVER_API_KEY='replace-with-a-secret' \
  ghcr.io/jgreencolon-sketch/remove-ai-marks-service:latest
```

## API

### Health

```bash
curl http://127.0.0.1:8765/health
```

### Capabilities

```bash
curl http://127.0.0.1:8765/capabilities
```

### Inspect

```bash
curl -X POST http://127.0.0.1:8765/inspect \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"image.png\",\"file\":\"$(base64 -w0 image.png)\"}"
```

### Clean

```bash
curl -X POST http://127.0.0.1:8765/clean \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"image.png\",\"file\":\"$(base64 -w0 image.png)\"}" \
  | python -c 'import json,sys,base64; sys.stdout.buffer.write(base64.b64decode(json.load(sys.stdin)["cleaned"]))' \
  > image.cleaned.png
```

When authentication is enabled, add:

```text
Authorization: Bearer replace-with-a-secret
```

## Development

```bash
python -m unittest discover -s tests -v
python -m app.server
```

Every push to `main` runs the tests, builds and smoke-tests the Docker image,
then publishes `latest` and commit-SHA tags to GitHub Container Registry.
