FROM python:alpine

WORKDIR /src

# Copy only the files needed for pip install
COPY setup.py pyproject.toml MANIFEST.in ./
COPY gixy/ ./gixy/

RUN pip install --upgrade pip setuptools wheel && pip install .  # NOSONAR - local package build

USER nobody

ENTRYPOINT ["gixy"]
