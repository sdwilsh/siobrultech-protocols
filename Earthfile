VERSION 0.6
FROM alpine

# renovate: datasource=docker depName=python versioning=docker
ARG PYTHON_VERSION=3.11

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

pre-commit-validate:
    # renovate: datasource=pypi depName=pre-commit
    ARG PRE_COMMIT_VERSION=3.3.1
    FROM +python-requirements
    WORKDIR /usr/src/app
    RUN pip install --no-cache-dir pre-commit==$PRE_COMMIT_VERSION
    COPY . .
    RUN pre-commit run --all-files --show-diff-on-failure

pyright-validate:
    # renovate: datasource=pypi depName=pyright
    ARG PYRIGHT_VERSION=1.1.308
    FROM +python-dev-requirements
    WORKDIR /usr/src/app
    RUN pip install --no-cache-dir pyright==$PYRIGHT_VERSION
    COPY pyproject.toml .
    COPY scripts .
    COPY siobrultech_protocols .
    COPY tests .
    RUN pyright

renovate-validate:
    # renovate: datasource=docker depName=renovate/renovate versioning=docker
    ARG RENOVATE_VERSION=35
    FROM renovate/renovate:$RENOVATE_VERSION
    WORKDIR /usr/src/app
    COPY renovate.json .
    RUN renovate-config-validator

lint:
    BUILD +pre-commit-validate
    BUILD +pyright-validate
    BUILD +renovate-validate
