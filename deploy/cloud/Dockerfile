# The cloud control plane image.
#
# Build from the repository root so the package and its metadata are in
# context:
#
#   docker build -f deploy/cloud/Dockerfile -t interlock-cloud .
#
# Only the core package and the ``cloud`` extra are installed: the console
# front end, the Rust scopes and the development extras have no part in the
# hosted plane.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md /app/
COPY interlock /app/interlock

RUN pip install --no-cache-dir '.[cloud]' \
    && useradd --system --uid 10001 --no-create-home interlock

# The plane writes nothing to the image: state lives in Postgres, and
# connector homes are host-local. A read-only rootfs is still asserted by the
# compose profile.
USER interlock

EXPOSE 8787 9101

ENTRYPOINT ["python3", "-m", "interlock.cloud"]
CMD ["--help"]
