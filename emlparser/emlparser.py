import base64
import datetime
import json
import os
import re
import tempfile
from tempfile import mkstemp
from urllib.parse import urlparse

import eml_parser
import eml_parser.regex

from assemblyline.odm import IP_ONLY_REGEX
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import BODY_FORMAT, Result, ResultSection, MaxExtractedExceeded


class EmlParser(ServiceBase):
    def __init__(self, config=None):
        super(EmlParser, self).__init__(config)

    def start(self):
        self.log.info(
            f"start() from {self.service_attributes.name} service called")

    @staticmethod
    def json_serial(obj):
        if isinstance(obj, datetime.datetime):
            serial = obj.isoformat()
            return serial

    def execute(self, request):
        parser = eml_parser.eml_parser.EmlParser(include_raw_body=True, include_attachment_data=True)

        content_str = request.file_contents
        # Replace null bytes (wastes time during slices)
        content_str = content_str.replace(b'\x00', b'')
        parsed_eml = parser.decode_email_bytes(content_str)

        result = Result()
        header = parsed_eml['header']

        if "from" in header:
            all_uri = set()

            for body_counter, body in enumerate(parsed_eml['body']):
                if request.get_param('extract_body_text'):
                    fd, path = mkstemp()
                    with open(path, 'w') as f:
                        f.write(body['content'])
                        os.close(fd)
                    request.add_extracted(path, "body_" + str(body_counter), "Body text")
                if "uri" in body:
                    for uri in body['uri']:
                        all_uri.add(uri)

            kv_section = ResultSection('Email Headers', body_format=BODY_FORMAT.KEY_VALUE, parent=result)

            # Basic tags
            kv_section.add_tag("network.email.address", header['from'].strip())
            for to in header['to']:
                kv_section.add_tag("network.email.address", to)
            kv_section.add_tag("network.email.date", str(header['date']).strip())
            kv_section.add_tag("network.email.subject", header['subject'].strip())

            # Add CCs to body and tags
            if 'cc' in header:
                for to in header['to']:
                    kv_section.add_tag("network.email.address", to.strip())

            # Add Message ID to body and tags
            if 'message-id' in header['header']:
                kv_section.add_tag("network.email.msg_id",  header['header']['message-id'][0].strip())

            # Add Tags for received IPs
            if 'received_ip' in header:
                for ip in header['received_ip']:
                    kv_section.add_tag('network.static.ip', ip.strip())

            # Add Tags for received Domains
            if 'received_domain' in header:
                for dom in header['received_domain']:
                    kv_section.add_tag('network.static.domain', dom.strip())

            # If we've found URIs, add them to a section
            if len(all_uri) > 0:
                uri_section = ResultSection('URIs Found:', parent=result)
                for uri in all_uri:
                    uri_section.add_line(uri)
                    uri_section.add_tag('network.static.uri', uri.strip())
                    parsed_url = urlparse(uri)
                    if parsed_url.hostname and re.match(IP_ONLY_REGEX, parsed_url.hostname):
                        uri_section.add_tag('network.static.ip', parsed_url.hostname)
                    else:
                        uri_section.add_tag('network.static.domain', parsed_url.hostname)

            # Bring all headers together...
            extra_header = header.pop('header', {})
            header.pop('received', None)
            header.update(extra_header)

            kv_section.body = json.dumps(header, default=self.json_serial)

            if "attachment" in parsed_eml:
                attachments = parsed_eml['attachment']
                for attachment in attachments:
                    fd, path = mkstemp()

                    with open(path, 'wb') as f:
                        f.write(base64.b64decode(attachment['raw']))
                        os.close(fd)
                    try:
                        request.add_extracted(path, attachment['filename'], "Attachment ")
                    except MaxExtractedExceeded:
                        self.log.warning(f"Extract limit reached on attachments: "
                                         f"{len(attachments) - attachments.index(attachment)} not added")
                        break
                ResultSection('Extracted Attachments:', body="\n".join(
                    [x['filename'] for x in attachments]), parent=result)

            if request.get_param('save_emlparser_output'):
                fd, temp_path = tempfile.mkstemp(dir=self.working_directory)
                with os.fdopen(fd, "w") as myfile:
                    myfile.write(json.dumps(parsed_eml, default=self.json_serial))
                request.add_supplementary(temp_path, "parsing.json",
                                          "These are the raw results of running GOVCERT-LU's eml_parser")
        else:
            self.log.warning("emlParser could not parse EML; no useful information in result's headers")

        request.result = result
