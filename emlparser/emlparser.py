import base64
import datetime
import eml_parser
import json
import os
import re
import tempfile

from assemblyline.odm import IP_ONLY_REGEX, EMAIL_REGEX
from assemblyline.common.identify import fileinfo
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import BODY_FORMAT, Result, ResultSection
from assemblyline_v4_service.common.task import MaxExtractedExceeded

from compoundfiles import CompoundFileInvalidMagicError, CompoundFileNoMiniFatError
from emlparser.convert_outlook.outlookmsgfile import load as msg2eml
from ipaddress import IPv4Address, ip_address
from tempfile import mkstemp
from urllib.parse import urlparse


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
        info = fileinfo(request.file_path)

        # Eliminate invalid Office candidates
        if 'document/office/unknown' == info['type'] and \
                any(word in info['magic'].lower() for word in ["can't", "cannot"]):
            # An Office file that can't be converted
            request.result = Result()
            return

        # Attempt conversion of file
        try:
            content_str = msg2eml(request.file_path).as_bytes()
        except CompoundFileInvalidMagicError:
            cs_hex = content_str.hex()
            # Starts with a msg file header or contains RootEntry within the file
            if cs_hex.startswith('E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29'.replace(" ", "").lower()) or \
                    '52 00 6F 00 6F 00 74 00 20 00 45 00 6E 00 74 00 72 00 79'.replace(" ", "").lower() in cs_hex:
                # OneNote file or extracted stream containing msg file. Extract service should pull these out.
                self.log.info('File contains a MSG file. Did Extract pull them out?')
                request.result = Result()
                return
            # Office file passed but not an email
            elif 'document/office' in info['type']:
                request.result = Result()
                return
            else:
                # This isn't an Office file to be converted (least not with this tool)
                pass
        except CompoundFileNoMiniFatError:
            # Has headers but no content
            request.result = Result()
            return

        parsed_eml = parser.decode_email_bytes(content_str)
        result = Result()
        header = parsed_eml['header']

        if "from" in header or 'to' in header:
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
            if header.get('from', None):
                kv_section.add_tag("network.email.address", header['from'].strip())
            [kv_section.add_tag("network.email.address", to.strip())
             for to in header['to'] if re.match(EMAIL_REGEX, to.strip())]

            kv_section.add_tag("network.email.date", str(header['date']).strip())
            kv_section.add_tag("network.email.subject", header['subject'].strip())

            # Add CCs to body and tags
            if 'cc' in header:
                [kv_section.add_tag("network.email.address", cc.strip())
                 for cc in header['cc'] if re.match(EMAIL_REGEX, cc.strip())]
            # Add Message ID to body and tags
            if 'message-id' in header['header']:
                kv_section.add_tag("network.email.msg_id",  header['header']['message-id'][0].strip())

            # Add Tags for received IPs
            if 'received_ip' in header:
                [kv_section.add_tag('network.static.ip', ip.strip())
                 for ip in header['received_ip'] if isinstance(ip_address(ip), IPv4Address)]

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
