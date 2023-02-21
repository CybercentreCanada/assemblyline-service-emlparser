import base64
import email
import json
import os
import re
import tempfile
from datetime import datetime
from ipaddress import IPv4Address, ip_address
from tempfile import mkstemp
from urllib.parse import urlparse

import eml_parser
from assemblyline.odm import EMAIL_REGEX, IP_ONLY_REGEX, FULL_URI
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import BODY_FORMAT, Result, ResultSection
from assemblyline_v4_service.common.task import MaxExtractedExceeded
from assemblyline_v4_service.common.utils import extract_passwords
from bs4 import BeautifulSoup
from mailparser.utils import msgconvert

from emlparser.convert_outlook.outlookmsgfile import load as msg2eml


class EmlParser(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)

        # eml_parser headers are typically lowercased
        self.header_filter = [filter.lower() for filter in config.get("header_filter", [])]

    def start(self):
        self.log.info(f"start() from {self.service_attributes.name} service called")

    @staticmethod
    def json_serial(obj):
        if isinstance(obj, datetime):
            serial = obj.isoformat()
            return serial
        elif isinstance(obj, bytes):
            try:
                text = obj.decode("ascii")
                return text
            except UnicodeDecodeError:
                b64 = base64.b64encode(obj)
                return b64
        return repr(obj)

    def execute(self, request):
        parser = eml_parser.EmlParser(include_raw_body=True, include_attachment_data=True)
        content_str = request.file_contents

        # Attempt conversion of potential Outlook file -> eml
        if request.file_type == "document/office/email":
            try:
                content_str = msg2eml(request.file_path).as_bytes()
            except Exception:
                # Try using mailparser to convert
                converted_path, _ = msgconvert(request.file_path)
                with open(converted_path, "rb") as f:
                    content_str = f.read()

        header_agg = {"From": set(), "To": set(), "Cc": set(), "Sent": set(), "Reply-To": set(), "Date": set()}
        obscured_img_tags = []
        # Assume this is an email saved in HTML format
        if request.file_type == "code/html":
            parsed_html = BeautifulSoup(content_str, "lxml")
            valid_headers = ["To:", "Cc:", "Sent:", "From:", "Subject:", "Reply-To:"]

            if not parsed_html.body or not any(header in parsed_html.body.text for header in valid_headers):
                # We can assume this is just an HTML doc (or lacking body), one of which we can't process
                request.result = Result()
                return

            # Can't trust 'Date' to determine the difference between HTML docs vs HTML emails
            valid_headers.append("Date:")

            html_email = email.message_from_bytes(content_str)
            generator_metadata_content = ""
            for meta in parsed_html.find_all("meta"):
                if meta.attrs.get("name", None) == "Generator":
                    generator_metadata_content = meta.attrs.get("content", "")
                    break

            # Process HTML emails generated from Outlook
            if generator_metadata_content == "Microsoft Word 15":
                paragraphs = parsed_html.body.find_all("p")
                # Likely an email that was exported with original email headers
                if any(header in paragraphs[0] for header in valid_headers):
                    for p in paragraphs:
                        if any(valid_header in p.text for valid_header in valid_headers):
                            h_key, h_value = p.text.replace("\xa0", "").replace("\r\n", " ").split(":", 1)
                            html_email[h_key] = h_value
                            # Subject line indicates the end of the email header, beginning of body
                            if "Subject" in p.text:
                                break
            # Process HTML emails from MS Exchange Server or missing top-level headers (aggregate headers)
            elif (
                generator_metadata_content == "Microsoft Word 15 (filtered medium)"
                or generator_metadata_content == "Microsoft Exchange Server"
                or generator_metadata_content == ""
            ):
                subject = None
                for div in parsed_html.find_all("div"):
                    # Header information within divs
                    if any(header in div.text for header in valid_headers) and "WordSection1" not in div.attrs.get(
                        "class", []
                    ):
                        # Usually expect headers to be \n separated in text output but check first
                        if "\n" in div.text:
                            for h in div.text.split("\n"):
                                if any(header in h for header in valid_headers):
                                    h_key, h_value = h.split(":", 1)

                                    # Implying some malformed message got mixed with the headers of another message
                                    if h_key not in valid_headers:
                                        for header in valid_headers:
                                            if header in h:
                                                h_key = header[:-1]

                                    # Use the latest message's subject (this maintains FW, RE, etc.)
                                    if h_key == "Subject" and not subject:
                                        subject = h_value
                                    elif h_key != "Subject":
                                        header_agg[h_key].add(h_value)
                        # Does this div contain another div that actually have the headers?
                        elif any(header in content.text for header in valid_headers for content in div.contents
                                 if content.name == 'div'):
                            # If so, move onto the div that actually contains what we want
                            continue

                        # Document was probably not well formatted, so we'll use the headers as delimiters
                        else:
                            header_offset_map = {}
                            # Determine the position of each header
                            for header in list(header_agg.keys()) + ["Subject"]:
                                if header in div.text:
                                    header_offset_map[div.text.index(header)] = header
                            # Use the positions and length of header name to determine an offset
                            for i in range(len(header_offset_map)):
                                sorted_keys = sorted(header_offset_map.keys())
                                header_name = header_offset_map[sorted_keys[i]]
                                offset = len(f"{header_name}: ") + sorted_keys[i]
                                value = (
                                    div.text[offset: sorted_keys[i + 1]]
                                    if i < len(header_offset_map) - 1
                                    else div.text[offset:]
                                )

                                if header_name == "Subject":
                                    subject = value
                                else:
                                    header_agg[header_name].add(value)
                # Inspect all images
                for img in parsed_html.find_all("img"):
                    # Raise a heuristic if it seems like the tag is being obscured
                    if img.attrs.get('width') == 0 or img.attrs.get('height') == 0:
                        obscured_img_tags.append(img.attrs)

                # Assign aggregated info to email object
                html_email["Subject"] = subject
                for key, value in header_agg.items():
                    html_email[key] = "; ".join(value)
            content_str = html_email.as_bytes()

        parsed_eml = parser.decode_email_bytes(content_str)
        result = Result()
        header = parsed_eml["header"]

        if "from" in header or "to" in header or parsed_eml.get('attachments'):
            all_uri = set()
            body_words = set(extract_passwords(header["subject"]))
            for body_counter, body in enumerate(parsed_eml["body"]):
                body_text = BeautifulSoup(body["content"]).text
                body_words.update(extract_passwords(body_text))
                if request.get_param("extract_body_text"):
                    fd, path = mkstemp()
                    with open(path, "w") as f:
                        f.write(body["content"])
                        os.close(fd)
                    request.add_extracted(path, "body_" + str(body_counter), "Body text")
                if "uri" in body:
                    for uri in body["uri"]:
                        all_uri.add(uri)
            # Words in the email body, used by extract to guess passwords
            request.temp_submission_data["email_body"] = list(body_words)

            kv_section = ResultSection("Email Headers", body_format=BODY_FORMAT.KEY_VALUE, parent=result)

            # Basic tags
            from_addr = header["from"].strip() if header.get("from", None) else None
            if from_addr and re.match(EMAIL_REGEX, from_addr):
                kv_section.add_tag("network.email.address", from_addr)
            [
                kv_section.add_tag("network.email.address", to.strip())
                for to in header["to"]
                if re.match(EMAIL_REGEX, to.strip())
            ]

            kv_section.add_tag("network.email.date", str(header["date"]).strip())

            subject = header["subject"].strip() if header.get("subject", None) else None
            if subject:
                kv_section.add_tag("network.email.subject", subject)

            # Add CCs to body and tags
            if "cc" in header:
                [
                    kv_section.add_tag("network.email.address", cc.strip())
                    for cc in header["cc"]
                    if re.match(EMAIL_REGEX, cc.strip())
                ]
            # Add Message ID to body and tags
            if "message-id" in header["header"]:
                kv_section.add_tag("network.email.msg_id", header["header"]["message-id"][0].strip())

            # Add Tags for received IPs
            if "received_ip" in header:
                for ip in header["received_ip"]:
                    ip = ip.strip()
                    try:
                        if isinstance(ip_address(ip), IPv4Address):
                            kv_section.add_tag("network.static.ip", ip)
                    except ValueError:
                        pass

            # Add Tags for received Domains
            if "received_domain" in header:
                for dom in header["received_domain"]:
                    kv_section.add_tag("network.static.domain", dom.strip())

            # If we've found URIs, add them to a section
            if len(all_uri) > 0:
                uri_section = ResultSection("URIs Found:", parent=result)
                for uri in all_uri:
                    for invalid_uri_char in ['"', "'", '<', '>']:
                        for u in uri.split(invalid_uri_char):
                            if re.match(FULL_URI, u):
                                uri = u
                                break
                    uri_section.add_line(uri)
                    uri_section.add_tag("network.static.uri", uri.strip())
                    parsed_url = urlparse(uri)
                    if parsed_url.hostname and re.match(IP_ONLY_REGEX, parsed_url.hostname):
                        uri_section.add_tag("network.static.ip", parsed_url.hostname)
                    else:
                        uri_section.add_tag("network.static.domain", parsed_url.hostname)

            # Bring all headers together...
            extra_header = header.pop("header", {})
            header.pop("received", None)
            header.update(extra_header)

            # Convert to common format
            header["date"] = [self.json_serial(header["date"])]

            # Replace with aggregated date(s) if any available
            if header_agg["Date"]:
                # Replace
                if any(
                    default_date in header["date"]
                    for default_date in ["1970-01-01T00:00:00", "Thu, 01 Jan 1970 00:00:00 +0000"]
                ):
                    header["date"] = list(header_agg["Date"])
                # Append
                else:
                    header["date"] += list(header_agg["Date"])
                (kv_section.add_tag("network.email.date", str(date).strip()) for date in header_agg["Date"])

            # Filter out useless headers from results
            self.log.debug(header.keys())
            [header.pop(h) for h in self.header_filter if h in header.keys()]
            kv_section.set_body(json.dumps(header, default=self.json_serial))

            attachments_added = []
            if "attachment" in parsed_eml:
                attachments = parsed_eml["attachment"]
                for attachment in attachments:
                    fd, path = mkstemp()

                    with open(path, "wb") as f:
                        f.write(base64.b64decode(attachment["raw"]))
                        os.close(fd)
                    try:
                        if request.add_extracted(
                            path, attachment["filename"], "Attachment ", safelist_interface=self.api_interface
                        ):
                            attachments_added.append(attachment["filename"])
                    except MaxExtractedExceeded:
                        self.log.warning(
                            "Extract limit reached on attachments: "
                            f"{len(attachment) - len(attachments_added)} not added"
                        )
                        break
                ResultSection("Extracted Attachments:", body="\n".join([x for x in attachments_added]), parent=result)

            if request.get_param("save_emlparser_output"):
                fd, temp_path = tempfile.mkstemp(dir=self.working_directory)
                attachments = parsed_eml.get("attachment", [])
                # Remove raw attachments, all attachments up to MaxExtractedExceeded already extracted
                for attachment in attachments:
                    _ = attachment.pop("raw", None)
                with os.fdopen(fd, "w") as myfile:
                    myfile.write(json.dumps(parsed_eml, default=self.json_serial))
                request.add_supplementary(
                    temp_path, "parsing.json", "These are the raw results of running GOVCERT-LU's eml_parser"
                )

            if obscured_img_tags:
                ResultSection("Hidden IMG Tags found", body=json.dumps(obscured_img_tags),
                              body_format=BODY_FORMAT.JSON, heuristic=1, parent=result)
        else:
            self.log.warning("emlParser could not parse EML; no useful information in result's headers")

        request.result = result
