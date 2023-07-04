# EmlParser service

### EML message

This service is based of GOVCERT-LU eml_parser python library.

https://github.com/GOVCERT-LU/eml_parser

### Outlook message

This service evolved to better handle outlook messages using the extract-msg library.

https://github.com/TeamMsgExtractor/msg-extractor

#### Service Details

This service preforms the following actions:
- Extracts email header information
- Extracts email body urls
- Extracts Attachments
- Tags the various email addresses, URIs, domains, IPs, ...
- Optionally extracts email raw body
- Optionally return raw output from eml_parser lib
