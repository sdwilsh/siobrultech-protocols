VERSION 0.6
FROM alpine

# renovate: datasource=docker depName=python versioning=docker
ARG PYTHON_VERSION=3.12

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

pyright-validate:
    # renovate: datasource=pypi depName=pyright
    ARG PYRIGHT_VERSION=1.1.339
    FROM +python-dev-requirements
    WORKDIR /usr/src/app
    RUN pip install --no-cache-dir pyright==$PYRIGHT_VERSION
    COPY pyproject.toml .
    COPY --dir scripts .
    COPY --dir siobrultech_protocols .
    COPY --dir tests .
    RUN pyright

renovate-validate:
    # renovate: datasource=docker depName=renovate/renovate versioning=docker
    ARG RENOVATE_VERSION=37
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
