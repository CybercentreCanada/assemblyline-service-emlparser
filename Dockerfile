FROM cccs/assemblyline-v4-service-base:latest AS base

ENV SERVICE_PATH emlparser.emlparser.EmlParser

USER assemblyline

RUN pip install --no-cache-dir --user eml_parser[file-magic] && rm -rf ~/.cache/pip

# Clone Extract service code
WORKDIR /opt/al_service
COPY . .