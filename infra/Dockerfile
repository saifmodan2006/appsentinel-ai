FROM python:3.15-slim-bookworm AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SENTINEL_DATA=/data
WORKDIR /opt/sentinel
RUN groupadd -g 12001 sentinel && useradd -u 12001 -g 12001 -M sentinel \
    && mkdir -p /data /exchange/in /exchange/out \
    && chown -R sentinel:sentinel /data /exchange && chmod 700 /data /exchange/in /exchange/out
COPY requirements.txt .
RUN pip install --no-cache-dir pip==26.3 && pip install --no-cache-dir -r requirements.txt
USER 12001:12001

FROM base AS api
COPY sentinel sentinel
COPY apps/web apps/web
CMD ["python", "-m", "uvicorn", "sentinel.api:app", "--host", "0.0.0.0", "--port", "8000", "--limit-concurrency", "64"]

FROM base AS scanner
USER root
RUN apt-get update && apt-get install -y --no-install-recommends apksigner openjdk-17-jre-headless \
    && rm -rf /var/lib/apt/lists/*
COPY requirements-scanner.txt .
RUN pip install --no-cache-dir -r requirements-scanner.txt
ENV SENTINEL_APKSIGNER_JAR=/usr/share/java/apksigner.jar
COPY sentinel sentinel
USER 12001:12001
CMD ["python", "-m", "sentinel.sandbox"]

FROM scanner AS fixtures
USER root
RUN apt-get update && apt-get install -y --no-install-recommends aapt android-framework-res openjdk-17-jdk-headless \
    && rm -rf /var/lib/apt/lists/*
COPY tests/fixture-src /fixture
RUN mkdir /fixture/output && sh /fixture/make.sh /fixture/output

FROM fixtures AS qa
COPY requirements-dev.txt requirements-ml.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt -r requirements-ml.txt
COPY apps/web apps/web
COPY ml ml
COPY scripts scripts
COPY tests tests
COPY pyproject.toml .
ENV SENTINEL_TEST_FIXTURES=/fixture/output
USER 12001:12001
CMD ["python", "-m", "pytest", "-q"]
