FROM cccs/assemblyline-v4-service-base:latest AS base

ENV SERVICE_PATH emlparser.emlparser.EmlParser

USER root
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

USER assemblyline
RUN pip install -U --no-cache-dir --user eml_parser git+https://github.com/JoshData/convert-outlook-msg-file.git && rm -rf ~/.cache/pip

# Clone Extract service code
WORKDIR /opt/al_service
COPY . .

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
