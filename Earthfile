VERSION 0.6
FROM alpine

# renovate: datasource=docker depName=python versioning=docker
ARG PYTHON_VERSION=3.13

python-requirements:
    FROM python:$PYTHON_VERSION
    WORKDIR /usr/src/app
    COPY requirements.txt .
    COPY setup.cfg .
    COPY setup.py .
    RUN pip install --no-cache-dir -r requirements.txt

python-dev-requirements:
    FROM +python-requirements
    WORKDIR /usr/src/app
    COPY requirements-dev.txt .
    RUN pip install --no-cache-dir -r requirements-dev.txt

black-validate:
    FROM +python-dev-requirements
    WORKDIR /usr/src/app
    COPY --dir scripts .
    COPY --dir siobrultech_protocols .
    COPY --dir tests .
    RUN black . --check --diff --color

pyright-image:
    FROM +python-dev-requirements
    RUN nodeenv /.cache/nodeenv
    ENV PYRIGHT_PYTHON_ENV_DIR=/.cache/nodeenv
    WORKDIR /usr/src/app

pyright-validate:
    FROM +pyright-image
    WORKDIR /usr/src/app
    COPY pyproject.toml .
    COPY --dir scripts .
    COPY --dir siobrultech_protocols .
    COPY --dir tests .
    RUN pyright

renovate-validate:
    # renovate: datasource=docker depName=renovate/renovate versioning=docker
    ARG RENOVATE_VERSION=38
    FROM renovate/renovate:$RENOVATE_VERSION
    WORKDIR /usr/src/app
    COPY renovate.json .
    RUN renovate-config-validator

ruff-validate:
    FROM +python-dev-requirements
    WORKDIR /usr/src/app
    COPY pyproject.toml .
    COPY --dir scripts .
    COPY --dir siobrultech_protocols .
    COPY --dir tests .
    RUN ruff check . --diff

lint:
    BUILD +black-validate
    BUILD +pyright-validate
    BUILD +renovate-validate
    BUILD +ruff-validate
