FROM cccs/assemblyline-v4-service-base:latest AS base

ENV SERVICE_PATH emlparser.emlparser.EmlParser

USER root
RUN echo 'deb http://deb.debian.org/debian stretch-backports main' >> /etc/apt/sources.list
RUN apt-get update && apt-get install -y libemail-outlook-message-perl git && rm -rf /var/lib/apt/lists/*

USER assemblyline

# Temporary workaround until PR is merged: https://github.com/GOVCERT-LU/eml_parser/pull/59
RUN pip install -U --no-cache-dir --user compoundfiles compressed-rtf mail-parser bs4 lxml git+https://github.com/cccs-rs/eml_parser.git && rm -rf ~/.cache/pip

# Clone Extract service code
WORKDIR /opt/al_service
COPY . .

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
