[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline\_service\_emlparser-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline-service-emlparser)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/service-emlparser)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:service-emlparser)
[![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline-service-emlparser)](./LICENSE)
# EmlParser Service

This service parses emails using GOVCERT-LU eml_parser library while extracting header information, attachments, and URIs.

## Service Details
This service preforms the following actions:
- Extracts email header information
- Extracts email body urls
- Extracts Attachments
- Tags the various email addresses, URIs, domains, IPs, ...
- Optionally extracts email raw body
- Optionally return raw output from eml_parser lib

### Supporting Tools
 - [GOVCERT-LU eml_parser](https://github.com/GOVCERT-LU/eml_parser) python library for parsing EML files.
 - [extract-msg](https://github.com/TeamMsgExtractor/msg-extractor) library for parsing Outlook files.

## Image variants and tags

Assemblyline services are built from the [Assemblyline service base image](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
which is based on Debian 11 with Python 3.11.

Assemblyline services use the following tag definitions:

| **Tag Type** | **Description**                                                                                  |      **Example Tag**       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

## Running this service

This is an Assemblyline service. It is designed to run as part of the Assemblyline framework.

If you would like to test this service locally, you can run the Docker image directly from the a shell:

    docker run \
        --name EmlParser \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-emlparser

To add this service to your Assemblyline deployment, follow this
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

General Assemblyline documentation can be found at: https://cybercentrecanada.github.io/assemblyline4_docs/

# Service EmlParser

Ce service analyse les courriels à l'aide de la bibliothèque eml_parser de GOVCERT-LU tout en extrayant les informations d'en-tête, les pièces jointes et les URI.

## Détails du service
Ce service effectue les actions suivantes :
- Extraction des informations de l'en-tête du courrier électronique
- Extraction des URL du corps de l'e-mail
- Extraction des pièces jointes
- Étiquette les différentes adresses électroniques, URI, domaines, IP, ...
- Optionnellement, extrait le corps brut de l'email
- Optionnellement, renvoie la sortie brute de eml_parser lib

### Outils de support
 - [GOVCERT-LU eml_parser](https://github.com/GOVCERT-LU/eml_parser) bibliothèque python pour l'analyse des fichiers EML.
 - [extract-msg](https://github.com/TeamMsgExtractor/msg-extractor) bibliothèque pour analyser les fichiers Outlook.

## Variantes et étiquettes d'image

Les services d'Assemblyline sont construits à partir de l'image de base [Assemblyline service](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
qui est basée sur Debian 11 avec Python 3.11.

Les services d'Assemblyline utilisent les définitions d'étiquettes suivantes:

| **Type d'étiquette** | **Description**                                                                                                |  **Exemple d'étiquette**   |
| :------------------: | :------------------------------------------------------------------------------------------------------------- | :------------------------: |
|   dernière version   | La version la plus récente (peut être instable).                                                               |          `latest`          |
|      build_type      | Type de construction utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. |     `stable` ou `dev`      |
|        série         | Détails de construction complets, comprenant la version et le type de build: `version.buildType`.              | `4.5.stable`, `4.5.1.dev3` |

## Exécution de ce service

Ce service est spécialement optimisé pour fonctionner dans le cadre d'un déploiement d'Assemblyline.

Si vous souhaitez tester ce service localement, vous pouvez exécuter l'image Docker directement à partir d'un terminal:

    docker run \
        --name EmlParser \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-emlparser

Pour ajouter ce service à votre déploiement d'Assemblyline, suivez ceci
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/fr/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

La documentation générale sur Assemblyline peut être consultée à l'adresse suivante: https://cybercentrecanada.github.io/assemblyline4_docs/
