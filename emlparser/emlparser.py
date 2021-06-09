import base64
import datetime
import eml_parser
import email
import json
import os
import re
import tempfile

from assemblyline.odm import IP_ONLY_REGEX, EMAIL_REGEX
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import BODY_FORMAT, Result, ResultSection
from assemblyline_v4_service.common.task import MaxExtractedExceeded

from bs4 import BeautifulSoup
from compoundfiles import CompoundFileInvalidMagicError
from emlparser.convert_outlook.outlookmsgfile import load as msg2eml
from mailparser.utils import msgconvert
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

        # Attempt conversion of potential Outlook file -> eml
        try:
            content_str = msg2eml(request.file_path).as_bytes()
        except CompoundFileInvalidMagicError:
            # Not an Office file to be converted
            pass
        except:
            # Try using mailparser to convert
            converted_path, _ = msgconvert(request.file_path)
            content_str = open(converted_path, 'rb').read()

        # Assume this is an email saved in HTML format
        if request.file_type == 'code/html':
            parsed_html = BeautifulSoup(content_str, 'lxml')
            html_email = email.message_from_bytes(content_str)
            valid_headers = ['To:', 'Cc:', 'Sent:', 'From:', 'Subject:']
            if not parsed_html or not any(header in parsed_html.body.text for header in valid_headers):
                # We can assume this is just an HTML doc, one of which we're not meant to process
                # Or this is a file that identified as 'code/html' but isn't really HTML
                request.result = Result()
                return

            paragraphs = parsed_html.body.find_all('p')
            # Parse according to how Microsoft exports MSG -> HTML
            if b'Microsoft' in content_str:
                # Likely an email that was exported with original email headers
                if any(header in paragraphs[0] for header in valid_headers):
                    for p in paragraphs:
                        if any(valid_header in p.text for valid_header in valid_headers):
                            h_key, h_value = p.text.replace('\xa0', '').replace('\r\n', ' ').split(':', 1)
                            html_email[h_key] = h_value
                            # Subject line indicates the end of the email header, beginning of body
                            if 'Subject' in p.text:
                                break
                # Assuming this an email thread missing top-level header info, aggregate headers from previous messages
                else:
                    header_agg = {
                        "From": [],
                        "To": [],
                        "Cc": [],
                        "Sent": [],
                    }
                    subject = None

                    for div in parsed_html.find_all('div'):
                        # Looking for line breaks that are rendered in HTML
                        if "border-top:solid" in div.attrs.get('style', ""):
                            # Usually expected headers are within the div
                            for h in div.text.split('\n'):
                                if any(header in h for header in valid_headers):
                                    h_key, h_value = h.split(':', 1)
                                    if h_key == "Subject":
                                        subject = h_value
                                    else:
                                        header_agg[h_key].append(h_value)
                    # Assign aggregated info to email object
                    html_email['Subject'] = subject
                    for key, value in header_agg.items():
                        html_email[key] = '; '.join(value)
                content_str = html_email.as_bytes()

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
            from_addr = header['from'].strip() if header.get('from', None) else None
            if from_addr and re.match(EMAIL_REGEX, from_addr):
                kv_section.add_tag("network.email.address", from_addr)
            [kv_section.add_tag("network.email.address", to.strip())
             for to in header['to'] if re.match(EMAIL_REGEX, to.strip())]

            kv_section.add_tag("network.email.date", str(header['date']).strip())

            subject = header['subject'].strip() if header.get('subject', None) else None
            if subject:
                kv_section.add_tag("network.email.subject", subject)

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
