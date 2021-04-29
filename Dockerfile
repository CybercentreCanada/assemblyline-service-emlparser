FROM cccs/assemblyline-v4-service-base:latest AS base

ENV SERVICE_PATH emlparser.emlparser.EmlParser

USER assemblyline
RUN pip install -U --no-cache-dir --user eml_parser compoundfiles compressed-rtf && rm -rf ~/.cache/pip

# Clone Extract service code
WORKDIR /opt/al_service
COPY . .

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
