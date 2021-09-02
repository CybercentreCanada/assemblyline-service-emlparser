ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch AS base

ENV SERVICE_PATH emlparser.emlparser.EmlParser

USER root
RUN echo 'deb http://deb.debian.org/debian stretch-backports main' >> /etc/apt/sources.list
RUN apt-get update && apt-get install -y libemail-outlook-message-perl && rm -rf /var/lib/apt/lists/*

USER assemblyline

RUN pip install -U --no-cache-dir --user compoundfiles compressed-rtf mail-parser bs4 lxml eml-parser && rm -rf ~/.cache/pip

# Clone Extract service code
WORKDIR /opt/al_service
COPY . .

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
