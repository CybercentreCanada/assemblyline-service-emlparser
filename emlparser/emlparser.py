import base64
import email
import email.header
import email.parser
import json
import os
import re
import shutil
import tempfile
import traceback
from datetime import datetime
from hashlib import sha256
from ipaddress import IPv4Address, ip_address
from typing import List, Optional
from urllib.parse import urlparse

import eml_parser
import extract_msg
from assemblyline.common import forge
from assemblyline.common.str_utils import safe_str
from assemblyline.odm import DOMAIN_REGEX, EMAIL_REGEX, FULL_URI, IP, IP_ONLY_REGEX, IP_REGEX, URI, Domain, Email
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    BODY_FORMAT,
    KVSectionBody,
    Result,
    ResultKeyValueSection,
    ResultMultiSection,
    ResultSection,
    ResultTableSection,
    TableRow,
    TableSectionBody,
    TextSectionBody,
)
from assemblyline_v4_service.common.task import MaxExtractedExceeded
from assemblyline_v4_service.common.utils import extract_passwords
from bs4 import BeautifulSoup, Comment
from mailparser.utils import msgconvert
from multidecoder.decoders.network import EMAIL_RE, find_domains, find_emails, find_ips, find_urls
from olefile.olefile import OleFileError

from emlparser.headers.parser import DnsResolver, EmailHeaders
from emlparser.headers.validation import (
    GeneralHeaderValidation,
    HeaderValidator,
    HeaderValidatorResponse,
    HeaderValidatorResponseKind,
    MxHeaderValidation,
    SpfHeaderValidation,
)

NETWORK_IOC_TYPES = ["uri", "email", "domain"]
IDENTIFY = forge.get_identify(use_cache=os.environ.get("PRIVILEGED", "false").lower() == "true")
IP_VALIDATOR = IP()
DOMAIN_VALIDATOR = Domain()
URI_VALIDATOR = URI()
EMAIL_VALIDATOR = Email()


def tag_is_valid(validator, value) -> bool:
    try:
        validator.check(value)
    except ValueError:
        return False
    return True


def clean_uri_from_body(uri):
    for invalid_uri_char in ['"', "'", "<", ">"]:
        for u in uri.split(invalid_uri_char):
            if re.match(FULL_URI, u):
                uri = u
                break
    return uri


def domain_is_an_email_username(domain, all_emails):
    # This should not be needed, but some domains are wrongly extracted from email usernames.
    # Example: username.french@domain.com eml_parser could extract username.fr as a domain.
    # Example: username.fr@domain.com eml_parser/MD could extract username.fr as a domain.
    for eml_adr in all_emails:
        if domain in eml_adr.split("@", 1)[0]:
            return True
    return False


class EmlParser(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)

        # eml_parser headers are typically lowercased
        self.header_filter = [filter.lower() for filter in config.get("header_filter", [])]

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
                return repr(b64)
        return repr(obj)

    def execute(self, request: ServiceRequest) -> None:
        request.result = Result()
        if request.file_type == "document/office/email":
            self.handle_outlook(request)
        elif request.file_type == "code/html":
            self.handle_html(request)
        elif request.file_type == "document/email":
            self.handle_eml(request, request.file_contents)

    def get_outlook_msg(self, request: ServiceRequest, overrideEncoding=None) -> extract_msg.msg_classes.msg.MSGFile:
        try:
            msg: extract_msg.msg_classes.msg.MSGFile = None
            msg = extract_msg.openMsg(
                request.file_path,
                overrideEncoding=overrideEncoding,
                errorBehavior=extract_msg.enums.ErrorBehavior.SUPPRESS_ALL,
            )
            if msg is None:
                return None
            # Recipients parsing is only triggered when accessed, and some files were using
            # the wrong encoding. We access it here to trigger the UnicodeDecodeError and
            # try again with cp1252 in case it works.
            msg.recipients
            return msg
        except (
            NotImplementedError,
            extract_msg.exceptions.InvalidFileFormatError,
            extract_msg.exceptions.StandardViolationError,
            extract_msg.exceptions.UnrecognizedMSGTypeError,
            extract_msg.exceptions.UnsupportedMSGTypeError,
            extract_msg.exceptions.UnknownCodepageError,
            OSError,
            IndexError,
            UnicodeDecodeError,
            OleFileError,
        ) as e1:
            if isinstance(e1, UnicodeDecodeError) and overrideEncoding is None:
                if msg is None:
                    try:
                        previous_string_encoding = extract_msg.msg_classes.msg.MSGFile(
                            request.file_path,
                            overrideEncoding=overrideEncoding,
                            errorBehavior=extract_msg.enums.ErrorBehavior.SUPPRESS_ALL,
                        ).stringEncoding
                    except Exception:
                        raise e1
                else:
                    previous_string_encoding = msg.stringEncoding

                required_encoding = None
                try:
                    msg = self.get_outlook_msg(request, overrideEncoding="cp1252")
                    msg.recipients
                    required_encoding = "cp1252"
                except Exception:
                    try:
                        msg = self.get_outlook_msg(request, overrideEncoding="chardet")
                        msg.recipients
                        required_encoding = "chardet"
                    except Exception:
                        ResultSection(
                            "Couldn't decode unicode",
                            parent=request.result,
                            body=(
                                f"String encoding {previous_string_encoding} was specified in outlook file "
                                "but chardet was not able to find the right character set."
                            ),
                        )

                if msg:
                    ResultSection(
                        "Wrong String Encoding Stored",
                        parent=request.result,
                        body=(
                            f"String encoding {previous_string_encoding} was specified in outlook file "
                            f"but {required_encoding} was needed for {msg.stringEncoding}."
                        ),
                    )
                return msg

            # OleFileError is an OSError, we can try to parse it to eml
            if isinstance(e1, OleFileError):
                pass
            elif isinstance(e1, OSError) and str(e1) != "incomplete OLE sector":
                raise

            if isinstance(e1, IndexError) and str(e1) == "tuple index out of range":
                tb = traceback.format_exc()
                # Found some very corrupted MessageSigned that are triggering this error with attachments
                # We'll just extract the information we can as an eml if it is the case
                if "entry['guid'] = guids[entry['guid_index']]" not in tb:
                    raise

            # We haven't found a solution to the error
            self.log.warning(e1, exc_info=True)

    def handle_outlook(self, request: ServiceRequest) -> None:
        msg: extract_msg.msg_classes.msg.MSGFile = self.get_outlook_msg(request)
        if msg is None:
            # If we can't use extract-msg, rely on converting to eml
            converted_path, _ = msgconvert(request.file_path)
            with open(converted_path, "rb") as f:
                content_str = f.read()
            os.remove(converted_path)
            self.handle_eml(request, content_str)
            return

        headers_section = ResultSection("Email Headers", body_format=BODY_FORMAT.KEY_VALUE, parent=request.result)

        headers = {}
        headers_key_lowercase = []
        for k, v in msg.header.items():
            if k.lower() in self.header_filter or v is None or v == "":
                continue
            # Some headers are repeating, like 'Received'
            if k in headers:
                headers[k] = "\n".join([headers[k], v])
            else:
                headers[k] = v
                headers_key_lowercase.append(k.lower())
            if k == "Received":
                for m in eml_parser.regexes.recv_dom_regex.findall(v):
                    # eml_parser is better at it than our DOMAIN_REGEX
                    try:
                        _ = ip_address(m)
                    except ValueError:
                        headers_section.add_tag("network.static.domain", m)
                for m in re.findall(IP_REGEX, v):
                    headers_section.add_tag("network.static.ip", m)
                for m in find_emails(v.encode()):
                    headers_section.add_tag("network.email.address", m.value)

        # Sometimes we have both "Date" and "date"
        if "Date" in headers:
            headers.pop("date", None)

        headers_section.set_body(json.dumps(headers, default=self.json_serial))

        validation_section = self.build_email_header_validation_section(
            subject=headers.get("Subject"),
            sender=headers.get("Sender"),
            _from=headers.get("From"),
            reply_to=headers.get("Reply-To"),
            return_path=headers.get("Return-Path"),
            received=msg.header.get_all("Received"),
            received_spf=msg.header.get_all("Received-SPF"),
        )
        if validation_section.subsections:
            request.result.add_section(validation_section)

        attributes_to_skip = [
            "attachments",
            "appointmentTimeZoneDefinitionEndDisplay",
            "appointmentTimeZoneDefinitionStartDisplay",
            "body",
            "cleanGlobalObjectID",
            "compressedRtf",
            "dateFormat",
            "datetimeFormat",
            "deencapsulatedRtf",
            "errorBehavior",
            "filename",
            "globalObjectID",
            "header",
            "headerDict",
            "headerFormatProperties",
            "headerText",
            "htmlBody",
            "htmlBodyPrepared",
            "htmlInjectableHeader",
            "kwargs",
            "named",
            "namedProperties",
            "path",
            "props",
            "rawAttachments",
            "recipients",
            "rtfBody",
            "rtfEncapInjectableHeader",
            "rtfPlainInjectableHeader",
            "sideEffects",
            "signedBody",
            "taskOrdinal",
            "treePath",
        ]
        attributes_section = ResultKeyValueSection("Email Attributes", parent=request.result)
        # Patch in all potentially interesting attributes that we don't already have
        for attribute in dir(msg):
            if (
                attribute.startswith("_")
                or attribute in attributes_to_skip
                or attribute.lower() in headers_key_lowercase
            ):
                continue
            try:
                value = getattr(msg, attribute)
            except Exception:
                continue
            if callable(value):
                continue
            if value is None or value == "":
                continue
            attributes_section.set_item(attribute, self.json_serial(value))

        # Try to tag interesting fields
        def tag_field(tag, header_name, msg_name):
            # Sanitize input before tagging
            def sanitize(value):
                if tag == "network.email.msg_id":
                    # Remove any whitespace and remove <> surround MSG ID
                    value = value.strip().strip("<>")
                elif tag == "network.email.address":
                    match = re.search(EMAIL_RE, value.encode())
                    if match:
                        value = match.group(0)
                return value

            if header_name and header_name in headers and headers[header_name]:
                value = sanitize(headers[header_name])
                if value:
                    headers_section.add_tag(tag, value)
                    return
            # Either we are interested in the attribute, or the header was not present,
            # or the value of the header was not valid
            if msg_name and hasattr(msg, msg_name) and getattr(msg, msg_name):
                value = sanitize(getattr(msg, msg_name))
                if value:
                    attributes_section.add_tag(tag, value)

        tag_field("network.email.address", "From", "sender")
        tag_field("network.email.address", "Reply-To", None)
        tag_field("network.email.address", "In-Reply-To", "inReplyTo")
        tag_field("network.email.address", "Return-Path", None)
        for recipient in msg.recipients:
            headers_section.add_tag("network.email.address", recipient.email)
        tag_field("network.email.date", "Date", "date")
        tag_field("network.email.subject", "Subject", "subject")
        tag_field("network.email.msg_id", "Message-Id", "messageId")

        if "X-MS-Exchange-Processed-By-BccFoldering" in headers:
            ip = headers["X-MS-Exchange-Processed-By-BccFoldering"].strip()
            try:
                if isinstance(ip_address(ip), IPv4Address):
                    headers_section.add_tag("network.static.ip", ip)
            except ValueError:
                pass

        attachments_added = []
        attachments = msg.attachments
        if not attachments and hasattr(msg, "rawAttachments"):
            attachments = msg.rawAttachments
            if attachments:
                ResultSection(
                    "Attachments extraction mismatch",
                    parent=request.result,
                    body=(
                        f"0 attachments were found, {len(attachments)} raw "
                        f"attachment{'s were' if len(attachments) > 1 else ' was'} processed instead."
                    ),
                )

        for attachment_index, attachment in enumerate(attachments):
            try:
                save_type, attachment_path = attachment.save(
                    customPath=self.working_directory, extractEmbedded=True, skipNotImplemented=True
                )
            except Exception:
                continue

            if save_type is extract_msg.constants.SaveType.NONE:
                continue

            attachment_name = attachment.getFilename()
            if not attachment_name or attachment_name.startswith("UnknownFilename"):
                attachment_name = f"UnknownFilename_{attachment_index}"

            # Since IDENTIFY.fileinfo() is calling safe_str, we need to make sure it'll work.
            # This could be removed if we decide to remove the call to safe_str in IDENTIFY.fileinfo().
            if safe_str(attachment_path) != attachment_path:
                shutil.move(attachment_path, safe_str(attachment_path))
                attachment_path = safe_str(attachment_path)

            try:
                if request.add_extracted(
                    attachment_path, attachment_name, "Attachment", safelist_interface=self.api_interface
                ):
                    attachments_added.append(attachment_name)

                # If attachment is an HTML file, perform further inspection
                if IDENTIFY.fileinfo(attachment_path, generate_hashes=False)["type"] == "code/html":
                    document = open(attachment_path, "rb").read()

                    # Check to see if there's any "defang_" prefixed tags
                    # Reference: https://github.com/robmueller/html-defang
                    if b"<!--defang_" not in document:
                        break

                    # Find all comments
                    enable_brackets = True
                    for i in BeautifulSoup(document).find_all(string=lambda t: isinstance(t, Comment)):
                        if "*SC*" in i:
                            # Ignore comments with these lines
                            continue
                        defanged_i = i.replace("defang_", "").encode()
                        if enable_brackets:
                            defanged_i = b"<" + defanged_i + b">"
                        else:
                            defanged_i = defanged_i

                        if defanged_i == b"<script>":
                            enable_brackets = False
                        elif defanged_i == b"/script":
                            enable_brackets = True
                            defanged_i = b"<" + defanged_i + b">"

                        document = document.replace(b"<!--" + i.encode() + b"-->", defanged_i)
                    # Strip "defang_" from any remaining defanged-prefixed tags that weren't commented
                    document = document.replace(b"defang_", b"")
                    refanged_fp = os.path.join(self.working_directory, f"{attachment_name}_refanged.html")
                    with open(refanged_fp, "wb") as fp:
                        fp.write(document)
                    request.add_extracted(refanged_fp, os.path.basename(refanged_fp), "refanged HTML email body")

                    # Extract any scripts for further analysis
                    for script in BeautifulSoup(document).select("script"):
                        if script.text:
                            js_sha256 = sha256(script.text.encode()).hexdigest()
                            js_fp = os.path.join(self.working_directory, f"{attachment_name}_{js_sha256}.js")
                            with open(js_fp, "w") as fp:
                                fp.write(script.text)
                            request.add_extracted(js_fp, os.path.basename(js_fp), "Extracted JS from HTML body")
            except MaxExtractedExceeded:
                self.log.warning(
                    "Extract limit reached on attachments: " f"{len(attachments) - len(attachments_added)} not added"
                )
                break

        body = None
        # TODO: In the future, msg.detectedBodies will return an enum value
        # which confirms which body types are directly present on the file
        try:
            body = msg.body
            if body is not None and not isinstance(body, bytes):
                body = body.encode()
        except UnicodeDecodeError:
            # Do our best to find some kind of body
            try:
                body = body.htmlBody
            except Exception:
                try:
                    body = body.rtfBody
                except Exception:
                    pass

        if body:
            # Extract IOCs from body
            [attributes_section.add_tag("network.static.ip", x.value) for x in find_ips(body)]
            [attributes_section.add_tag("network.static.domain", x.value) for x in find_domains(body)]
            [attributes_section.add_tag("network.static.uri", x.value) for x in find_urls(body)]
            [attributes_section.add_tag("network.email.address", x.value) for x in find_emails(body)]
            if request.get_param("extract_body_text"):
                with tempfile.NamedTemporaryFile(dir=self.working_directory, mode="wb", delete=False) as tmp_f:
                    tmp_f.write(body)
                request.add_extracted(
                    tmp_f.name, "email_body", "Extracted email body", safelist_interface=self.api_interface
                )

        if attachments_added:
            ResultSection(
                "Extracted Attachments:", parent=request.result, body="\n".join([x for x in attachments_added])
            )

            # Only extract passwords if there is an attachment
            body_words = set()
            if "Subject" in headers and headers["Subject"]:
                body_words.update(extract_passwords(headers["Subject"]))
            elif hasattr(msg, "subject") and msg.subject:
                body_words.update(extract_passwords(msg.subject))

            if body:
                try:
                    body_words.update(extract_passwords(body.decode()))
                    request.temp_submission_data["email_body"] = sorted(list(body_words))
                except UnicodeDecodeError:
                    # Couldn't decode the body correctly. We could get the bytes manually and decode what we can.
                    # For the moment, just return what we have, and the user will see if the attachment won't be
                    # extracted.
                    pass

        # Specialized fields
        if msg.namedProperties.get(("851F", extract_msg.constants.ps.PSETID_COMMON)) and msg.namedProperties.get(
            ("851F", extract_msg.constants.ps.PSETID_COMMON)
        ).startswith("\\\\"):
            plrfp = msg.namedProperties.get(("851F", extract_msg.constants.ps.PSETID_COMMON))
            heur_section = ResultKeyValueSection("CVE-2023-23397", parent=attributes_section)
            heur_section.add_tag("attribution.exploit", "CVE-2023-23397")
            heur_section.add_tag("network.static.unc_path", plrfp)
            heur_section.set_item("PidLidReminderFileParameter", plrfp)
            if msg.namedProperties.get(("851C", extract_msg.constants.ps.PSETID_COMMON)) is not None:
                heur_section.set_item(
                    "PidLidReminderOverride", msg.namedProperties.get(("851C", extract_msg.constants.ps.PSETID_COMMON))
                )
                if msg.namedProperties.get(("851C", extract_msg.constants.ps.PSETID_COMMON)):
                    heur_section.set_heuristic(2)
            file_location = plrfp.split("\\")
            if len(file_location) >= 3:
                try:
                    if isinstance(ip_address(file_location[2]), IPv4Address):
                        heur_section.add_tag("network.static.ip", file_location[2])
                except ValueError:
                    pass

    def handle_html(self, request: ServiceRequest) -> None:
        # Assume this is an email saved in HTML format
        content_str = request.file_contents
        try:
            parsed_html = BeautifulSoup(content_str, "lxml")
        except Exception:
            # This is not even a valid HTML, not worth trying to parse it.
            return

        valid_headers = ["To:", "Cc:", "Sent:", "From:", "Subject:", "Reply-To:"]

        if not parsed_html.body or not any(header in parsed_html.body.text for header in valid_headers):
            # We can assume this is just an HTML doc (or lacking body), one of which we can't process
            return

        # Can't trust 'Date' to determine the difference between HTML docs vs HTML emails
        valid_headers.append("Date:")

        html_email = email.message_from_bytes(content_str)
        generator_metadata_content = ""
        for meta in parsed_html.find_all("meta"):
            if meta.attrs.get("name", None) == "Generator":
                generator_metadata_content = meta.attrs.get("content", "")
                break

        header_agg = {"From": set(), "To": set(), "Cc": set(), "Sent": set(), "Reply-To": set(), "Date": set()}

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
                    if "\n" in div.text.strip():
                        for h in div.text.split("\n"):
                            if any(header in h for header in valid_headers):
                                h_key, h_value = h.split(":", 1)

                                # Implying some malformed message got mixed with the headers of another message
                                if h_key not in valid_headers:
                                    for header in valid_headers:
                                        if header in h:
                                            h_key = header[:-1]

                                h_value = h_value.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")

                                # Use the latest message's subject (this maintains FW, RE, etc.)
                                if h_key == "Subject" and not subject:
                                    subject = h_value
                                elif h_key != "Subject":
                                    header_agg[h_key].add(h_value)
                    # Does this div contain another div that actually have the headers?
                    elif any(
                        header in content.text
                        for header in valid_headers
                        for content in div.contents
                        if content.name == "div"
                    ):
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
                                div.text[offset : sorted_keys[i + 1]]
                                if i < len(header_offset_map) - 1
                                else div.text[offset:]
                            )
                            value = value.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")

                            if header_name == "Subject":
                                subject = value
                            else:
                                header_agg[header_name].add(value)

            obscured_img_tags = []
            # Inspect all images
            for img in parsed_html.find_all("img"):
                # Raise a heuristic if it seems like the tag is being obscured
                if img.attrs.get("width") == 0 or img.attrs.get("height") == 0:
                    obscured_img_tags.append(img.attrs)
            if obscured_img_tags:
                ResultSection(
                    "Hidden IMG Tags found",
                    body=json.dumps(obscured_img_tags),
                    body_format=BODY_FORMAT.JSON,
                    heuristic=1,
                    parent=request.result,
                )

            # Assign aggregated info to email object
            html_email["Subject"] = subject
            for key, value in header_agg.items():
                html_email[key] = "; ".join(value)
        content_str = html_email.as_bytes()

        self.handle_eml(request, content_str, header_agg)

    def handle_eml(self, request: ServiceRequest, content_str, header_agg={}) -> None:
        parser = eml_parser.EmlParser(include_raw_body=True, include_attachment_data=True)
        try:
            parsed_eml = parser.decode_email_bytes(content_str)
        except Exception as e:
            exception_handled = False

            if (
                not exception_handled
                and isinstance(e, ValueError)
                and str(e) in ["hour must be in 0..23", "day is out of range for month"]
            ):
                # Invalid date given in headers, strip section and reprocess
                content_str = content_str.replace(re.findall(b"Date:.*\n", content_str)[0], b"")
                parsed_eml = parser.decode_email_bytes(content_str)
                exception_handled = True

            if (
                not exception_handled
                and isinstance(e, ValueError)
                and str(e) == "invalid arguments; address parts cannot contain CR or LF"
            ):
                for address_field in [b"To:", b"CC:", b"From:"]:
                    if content_str[: len(address_field)] == address_field:
                        to_start_index = 0
                    elif b"\n" + address_field in content_str:
                        to_start_index = content_str.index(b"\n" + address_field) + 1
                    else:
                        continue
                    to_end_index = re.search(rb"\n\S", content_str[to_start_index + len(address_field) :]).start()

                    email_header = email.header.decode_header(
                        content_str[
                            to_start_index + len(address_field) : to_start_index + len(address_field) + to_end_index
                        ].decode()
                    )

                    email_header = [
                        (
                            (x[0] if isinstance(x[0], bytes) else x[0].encode())
                            .replace(b"\r\n", b"")
                            .replace(b"\n", b""),
                            x[1],
                        )
                        for x in email_header
                    ]

                    content_str = (
                        content_str[:to_start_index]
                        + address_field
                        + b" "
                        + email.header.make_header(email_header, header_name=address_field[1:-1]).encode().encode()
                        + content_str[to_start_index + len(address_field) + to_end_index :]
                    )
                parsed_eml = parser.decode_email_bytes(content_str)
                exception_handled = True

            if not exception_handled and request.file_type == "code/html":
                # Conversion of HTML → EML failed, likely because of malformed content
                return

            tb = traceback.format_exc()

            EXPECT_ATOM_TXT = "expected atom at a start of dot-atom-text but found"
            if not exception_handled and isinstance(e, IndexError) and EXPECT_ATOM_TXT in tb:
                bad_dot_atom_text = re.search(f"{EXPECT_ATOM_TXT} '(.*)'\n", tb).group(1).encode()
                # bad_dot_atom_text can contain brackets, so can't use it in a regex
                # We'll delete all lines containing what we can't parse, as we don't know which one is causing the error
                while bad_dot_atom_text in content_str:
                    index = content_str.index(bad_dot_atom_text)
                    try:
                        before = content_str.rindex(b"\n", 0, index)
                    except ValueError:
                        before = 0
                    try:
                        after = content_str.index(b"\n", index + len(bad_dot_atom_text))
                    except ValueError:
                        after = len(content_str)
                    content_str = content_str[:before] + content_str[after:]
                parsed_eml = parser.decode_email_bytes(content_str)
                exception_handled = True

            UNEXPECTED_ADDR_ENDING = "at end of group display name but found"
            if not exception_handled and isinstance(e, IndexError) and UNEXPECTED_ADDR_ENDING in tb:
                unexpected_addr_ending_text = re.search(f"{UNEXPECTED_ADDR_ENDING} '(.*)'\n", tb).group(1).encode()
                content_str = content_str.replace(unexpected_addr_ending_text + b"\r\n", b"\r\n")
                content_str = content_str.replace(unexpected_addr_ending_text + b"\n", b"\n")
                parsed_eml = parser.decode_email_bytes(content_str)
                exception_handled = True

            PARSEDATE_TZ = "_parsedate_tz(data)"
            if (
                not exception_handled
                and isinstance(e, TypeError)
                and str(e) == "cannot unpack non-iterable NoneType object"
                and PARSEDATE_TZ in tb
            ):
                for date_to_delete in re.findall(b"\n.*Date:.*\n", content_str):
                    content_str = content_str.replace(date_to_delete, b"\n")
                parsed_eml = parser.decode_email_bytes(content_str)
                exception_handled = True

            if (
                not exception_handled
                and isinstance(e, TypeError)
                and str(e) == "expected string or buffer"
                and "workaround_bug_27257" in tb
            ):
                for address_field in [b"\nTo:", b"\nCC:", b"\nFrom:"]:
                    if address_field not in content_str:
                        continue
                    to_start_index = content_str.index(address_field)
                    to_end_index = re.search(rb"\n\S", content_str[to_start_index + len(address_field) :]).start()
                    content_str = (
                        content_str[: to_start_index + len(address_field)]
                        + content_str[
                            to_start_index + len(address_field) : to_start_index + len(address_field) + to_end_index
                        ].replace(b":", b"")
                        + content_str[to_start_index + len(address_field) + to_end_index :]
                    )
                parsed_eml = parser.decode_email_bytes(content_str)
                exception_handled = True

            if not exception_handled and all(term in tb for term in ["if value[0] == '>':", "get_angle_addr"]):
                # An email was detected but is incomplete
                return

            if not exception_handled:
                raise e

        header = parsed_eml["header"]
        if str(header["date"]).strip() in [
            "1970-01-01T00:00:00",
            "Thu, 01 Jan 1970 00:00:00 +0000",
            "1970-01-01 00:00:00+00:00",
        ]:
            header.pop("date")

        if not ("from" in header or "to" in header or parsed_eml.get("attachments")):
            self.log.warning("emlParser could not parse EML; no useful information in result's headers")
            return

        all_iocs = {}
        [all_iocs.setdefault(t, set()) for t in NETWORK_IOC_TYPES]
        md_iocs = all_iocs.copy()
        body_words = set(extract_passwords(header["subject"]))
        for body_counter, body in enumerate(parsed_eml["body"]):
            body_text = BeautifulSoup(body["content"]).text
            body_words.update(extract_passwords(body_text))
            # Always extract html so other modules can analyze it
            if request.get_param("extract_body_text") or "html" in body.get("content_type", "unknown"):
                fd, path = tempfile.mkstemp(dir=self.working_directory)
                with open(path, "w") as f:
                    f.write(body["content"])
                    os.close(fd)
                request.add_extracted(path, "body_" + str(body_counter), "Body text")
            for ioc_type in NETWORK_IOC_TYPES:
                # Process eml_parser extracted IOCs
                new_ioc = set(body.get(ioc_type, []))
                if not new_ioc:
                    continue
                if ioc_type == "uri":
                    new_ioc = set(map(clean_uri_from_body, new_ioc))
                all_iocs[ioc_type] = all_iocs[ioc_type].union(new_ioc)

                # Process MultiDecoder extracted IOCs
                new_ioc = []
                encoded_body_content = body["content"].encode()
                if ioc_type == "domain":
                    for x in find_domains(encoded_body_content):
                        if tag_is_valid(DOMAIN_VALIDATOR, x.value.decode()):
                            new_ioc.append(x.value.decode())

                if ioc_type == "email":
                    for x in find_emails(encoded_body_content):
                        if tag_is_valid(EMAIL_VALIDATOR, x.value.decode()):
                            new_ioc.append(x.value.decode())

                if ioc_type == "uri":
                    for x in find_urls(encoded_body_content):
                        if tag_is_valid(URI_VALIDATOR, x.value.decode()):
                            new_ioc.append(x.value.decode())
                md_iocs[ioc_type] = md_iocs[ioc_type].union(new_ioc)

        # Words in the email body, used by Extract to guess passwords
        request.temp_submission_data["email_body"] = sorted(list(body_words))

        kv_section = ResultSection("Email Headers", body_format=BODY_FORMAT.KEY_VALUE, parent=request.result)

        # Basic tags
        from_addr = header["from"].strip() if header.get("from", None) else None
        if from_addr and re.match(EMAIL_REGEX, from_addr):
            kv_section.add_tag("network.email.address", from_addr)
        [
            kv_section.add_tag("network.email.address", to.strip())
            for to in header["to"]
            if re.match(EMAIL_REGEX, to.strip())
        ]

        parsed_headers = email.message_from_bytes(content_str)
        validation_section = self.build_email_header_validation_section(
            subject=header.get("subject"),
            sender=parsed_headers.get("sender"),
            _from=parsed_headers.get("from"),
            reply_to=parsed_headers.get("reply-to"),
            return_path=parsed_headers.get("return-path"),
            received=parsed_headers.get_all("received"),
            received_spf=parsed_headers.get_all("received-spf"),
        )
        if validation_section.subsections:
            request.result.add_section(validation_section)

        if "date" in header:
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
            kv_section.add_tag("network.email.msg_id", header["header"]["message-id"][0].strip().strip("<>"))

        # Add Tags for received IPs
        if "received_ip" in header:
            header["received_ip"] = sorted(header["received_ip"])
            for ip in header["received_ip"]:
                ip = ip.strip()
                try:
                    if isinstance(ip_address(ip), IPv4Address):
                        kv_section.add_tag("network.static.ip", ip)
                except ValueError:
                    pass

        # Add Tags for received Domains
        if "received_domain" in header:
            header["received_domain"] = sorted(header["received_domain"])
            for dom in header["received_domain"]:
                kv_section.add_tag("network.static.domain", dom.strip())

        # If we've found URIs, add them to a section
        if all_iocs["uri"] or md_iocs["uri"]:
            md_uris_lowercase = [x.lower() for x in md_iocs["uri"]]
            all_iocs["uri"] = [x for x in all_iocs["uri"] if x.lower() not in md_uris_lowercase]
            uri_section = ResultSection("URIs Found:", parent=request.result)
            for uri in sorted(md_iocs["uri"]):
                try:
                    parsed_url = urlparse(uri)
                except ValueError:
                    continue
                uri_section.add_line(uri)
                uri_section.add_tag("network.static.uri", uri.strip())
                if parsed_url.hostname and re.match(IP_ONLY_REGEX, parsed_url.hostname):
                    uri_section.add_tag("network.static.ip", parsed_url.hostname)
                else:
                    uri_section.add_tag("network.static.domain", parsed_url.hostname)

            if all_iocs["uri"]:
                emlp_uri_section = ResultSection("URIs Found by eml_parser:")
                for uri in sorted(all_iocs["uri"]):
                    try:
                        parsed_url = urlparse(uri)
                    except ValueError:
                        continue
                    # This should not be needed, but eml_parser is wrongly extracting some URI multiple time,
                    # with some being only a subset of the real one. Example:
                    # Real URI in html: https://site.com/webpage/%3EUID%3E111?header=h&amp;part=1.1&amp;f=data01.jpg
                    # Other URI found: https://site.com/webpage/%3EUID%3E111?header=h&amp;part=1.1&amp;f=data0
                    # Other URI found: https://site.com/webpage/%3EUID%3E111?header=h&amp;pa
                    # Other URI found: https://site.com/webpage/%3EUID%3E111?he
                    # Other URI found: https://site.com/webpage/%3EUID%3E1
                    superseeding_uris = [u for u in all_iocs["uri"] if uri in u and uri != u]
                    if (
                        superseeding_uris
                        and len(parsed_url.path)
                        + len(parsed_url.params)
                        + len(parsed_url.query)
                        + len(parsed_url.fragment)
                        # Arbitrary length. This just makes sure we're not skipping small URIs that
                        # may have more chances to have a genuine superseeding uri in the bodies.
                        > 10
                    ):
                        # Skipping that URI as a longer one looks to be present
                        continue
                    emlp_uri_section.add_line(uri)
                    emlp_uri_section.add_tag("network.static.uri", uri.strip())
                    if parsed_url.hostname and re.match(IP_ONLY_REGEX, parsed_url.hostname):
                        emlp_uri_section.add_tag("network.static.ip", parsed_url.hostname)
                    else:
                        emlp_uri_section.add_tag("network.static.domain", parsed_url.hostname)
                if emlp_uri_section.body:
                    uri_section.add_subsection(emlp_uri_section)

        # If we've found domains, add them to a section
        if all_iocs["domain"] or md_iocs["domain"]:
            md_domains_lowercase = [x.lower() for x in md_iocs["domain"]]
            all_iocs["domain"] = [x for x in all_iocs["domain"] if x.lower() not in md_domains_lowercase]
            domain_section = ResultSection("Domains Found:", parent=request.result)
            for domain in sorted(md_iocs["domain"]):
                if domain_is_an_email_username(domain, md_iocs["email"]):
                    continue
                domain_section.add_line(domain)
                domain_section.add_tag("network.static.domain", domain)

            if all_iocs["domain"]:
                emlp_domain_section = ResultSection("Domains Found by eml_parser:")
                for domain in sorted(all_iocs["domain"]):
                    if not tag_is_valid(DOMAIN_VALIDATOR, domain):
                        continue
                    if domain_is_an_email_username(domain, md_iocs["email"].union(all_iocs["email"])):
                        continue
                    # This should not be needed, but eml_parser is wrongly extracting some domain multiple time,
                    # with some being only a subset of the real one. Example:
                    # Real domain: abc.com
                    # Other domain: bc.com
                    skip_domain = False
                    for d in all_iocs["domain"]:
                        # Make sure it's not simply a subdomain, where both domains would be valid
                        if domain != d and d.endswith(domain) and d[-len(domain) - 1] != ".":
                            skip_domain = True
                            break
                    if skip_domain:
                        continue
                    emlp_domain_section.add_line(domain)
                    emlp_domain_section.add_tag("network.static.domain", domain)
                if emlp_domain_section.body:
                    domain_section.add_subsection(emlp_domain_section)

        # If we've found email addresses, add them to a section
        if all_iocs["email"] or md_iocs["email"]:
            md_emails_lowercase = [x.lower() for x in md_iocs["email"]]
            all_iocs["email"] = [x for x in all_iocs["email"] if x.lower() not in md_emails_lowercase]
            email_section = ResultSection("Email Addresses Found:", parent=request.result)
            for eml_adr in sorted(md_iocs["email"]):
                email_section.add_line(eml_adr)
                email_section.add_tag("network.email.address", eml_adr)

            if all_iocs["email"]:
                emlp_email_section = ResultSection("Email Addresses Found by eml_parser:")
                for eml_adr in sorted(all_iocs["email"]):
                    if not re.match(EMAIL_REGEX, eml_adr):
                        continue
                    emlp_email_section.add_line(eml_adr)
                    emlp_email_section.add_tag("network.email.address", eml_adr)
                if emlp_email_section.body:
                    email_section.add_subsection(emlp_email_section)

        # Bring all headers together...
        extra_header = header.pop("header", {})
        header.pop("received", None)
        header.update(extra_header)

        # Convert to common format
        if "date" in header:
            header["date"] = [self.json_serial(header["date"])]

        # Replace with aggregated date(s) if any available
        if header_agg.get("Date"):
            # Replace
            if "date" not in header:
                header["date"] = list(header_agg["Date"])
            # Append
            else:
                header["date"] += list(header_agg["Date"])
            (kv_section.add_tag("network.email.date", str(date).strip()) for date in header_agg["Date"])

        # Filter out useless headers from results
        self.log.debug(header.keys())
        [header.pop(h) for h in self.header_filter if h in header.keys()]
        kv_section.set_body(json.dumps(header, default=self.json_serial, sort_keys=True))

        # Merge X-MS-Exchange-Organization-Persisted-Urls headers into one block
        if header.get("x-ms-exchange-organization-persisted-urls-chunkcount"):
            missing_persisted_urls_chunks = 0
            persisted_urls_block = ""
            block_count = int(header["x-ms-exchange-organization-persisted-urls-chunkcount"][0])
            for i in range(block_count):
                if f"x-ms-exchange-organization-persisted-urls-{i}" in header:
                    persisted_urls_block = "".join(
                        [persisted_urls_block, header[f"x-ms-exchange-organization-persisted-urls-{i}"][0]]
                    )
                else:
                    missing_persisted_urls_chunks += 1
            persisted_urls_block = persisted_urls_block.strip().encode()

            # Look for network IOCs in this block and tag them
            for x in find_domains(persisted_urls_block):
                if tag_is_valid(DOMAIN_VALIDATOR, x.value.decode()):
                    kv_section.add_tag("network.static.domain", x.value)

            for x in find_ips(persisted_urls_block):
                if tag_is_valid(IP_VALIDATOR, x.value.decode()):
                    kv_section.add_tag("network.static.ip", x.value)

            for x in find_urls(persisted_urls_block):
                if tag_is_valid(URI_VALIDATOR, x.value.decode()):
                    kv_section.add_tag("network.static.uri", x.value)

            if missing_persisted_urls_chunks != 0:
                missing_persisted_urls_chunks_section = ResultSection("Missing Persisted URLs chunks")
                block_found = block_count - missing_persisted_urls_chunks
                missing_persisted_urls_chunks_section.add_line(
                    f"Persisted URLs block found: {block_found}/{block_count} ({block_found/block_count*100:.0f}%)"
                )
                request.result.add_section(missing_persisted_urls_chunks_section)

        attachments_added = []
        if "attachment" in parsed_eml:
            attachments = parsed_eml["attachment"]
            for attachment in attachments:
                fd, path = tempfile.mkstemp(dir=self.working_directory)

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
                        "Extract limit reached on attachments: " f"{len(attachment) - len(attachments_added)} not added"
                    )
                    break
            if attachments_added:
                ResultSection(
                    "Extracted Attachments:", body="\n".join([x for x in attachments_added]), parent=request.result
                )

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

    def build_email_header_validation_section(
        self,
        subject: str,
        sender: Optional[str],
        _from: Optional[str],
        reply_to: Optional[str],
        return_path: Optional[str],
        received: Optional[List[str]],
        received_spf: Optional[List[str]],
    ) -> ResultSection:
        validation_section = ResultSection("Email Headers Validation")

        spf_section = ResultTableSection("SPF Validation")
        mx_section = ResultMultiSection("Sender MX Record Validation")
        general_sender_section = ResultMultiSection("General Sender Validation")

        validators: List[HeaderValidator] = [
            GeneralHeaderValidation(),
            SpfHeaderValidation(),
        ]

        dns_resolver = None
        if self.service_attributes.docker_config.allow_internet_access:
            dns_resolver = DnsResolver()
            validators.append(MxHeaderValidation(dns_resolver=dns_resolver))

        parsed_headers = EmailHeaders(
            subject=subject,
            sender=sender,
            _from=_from,
            reply_to=reply_to,
            return_path=return_path,
            received=received,
            received_spf=received_spf,
            dns_resolver=dns_resolver,
        )

        results = []
        for validator in validators:
            results.extend(validator.validate(parsed_headers))

        for result in results:
            match result.kind:
                case HeaderValidatorResponseKind.MX_DOMAIN_FROMDOMAIN_NOT_FOUND:
                    mx_section.add_section_part(TextSectionBody("Unable to extract fromdomain from headers"))
                case HeaderValidatorResponseKind.MX_DOMAIN_NOT_MATCHING:
                    mx_section.add_tag("network.static.domain", parsed_headers.received[-1].domain)
                    mx_section.add_tag("network.static.domain", result.data["domain"])
                    mx_section.add_section_part(TextSectionBody("Received domain not found in MX DNS records"))
                    self.add_mx_records_to_multi_section(mx_section, result, parsed_headers)
                case HeaderValidatorResponseKind.MX_DOMAIN_RECORD_MISSING:
                    mx_section.add_section_part(TextSectionBody(f"MX domain not found for {result.data}"))
                case HeaderValidatorResponseKind.MX_DOMAIN_VALID:
                    mx_section.add_tag("network.static.domain", parsed_headers.received[-1].domain)
                    mx_section.add_tag("network.static.domain", result.data["domain"])
                    mx_section.add_section_part(TextSectionBody("Received domain found in MX DNS records"))
                    self.add_mx_records_to_multi_section(mx_section, result, parsed_headers)
                case HeaderValidatorResponseKind.FROM_SENDER_DIFFER:
                    section = ResultKeyValueSection("From and Sender headers differ")
                    section.set_item("from address", parsed_headers._from.address)
                    section.set_item("sender address", parsed_headers.sender.address)
                    general_sender_section.add_subsection(section)
                case HeaderValidatorResponseKind.FROM_REPLY_TO_DIFFER:
                    section = ResultKeyValueSection("From and Reply-To headers differ")
                    section.set_item("from address", parsed_headers._from.address)
                    section.set_item("reply-to address", parsed_headers.reply_to.address)
                    general_sender_section.add_subsection(section)
                case HeaderValidatorResponseKind.FROM_RETURN_PATH_DIFFER:
                    section = ResultKeyValueSection("From and Return-Path headers differ")
                    section.set_item("from address", parsed_headers._from.address)
                    section.set_item("return-path address", parsed_headers.return_path.address)
                    general_sender_section.add_subsection(section)
                case HeaderValidatorResponseKind.EMAIL_DISPLAY_NAME_DIFFER:
                    section = ResultKeyValueSection(
                        "From display name header is an email and is a different email address of the From header"
                    )
                    section.set_item("from address", parsed_headers._from.address)
                    section.set_item("from display name", parsed_headers._from.name)
                    general_sender_section.add_subsection(section)
                case kind if kind in SpfHeaderValidation.ACTION_RESULT_MAPPING.values():
                    spf_section.add_tag("network.static.domain", result.data.domain)
                    spf_section.add_row(
                        TableRow(
                            action=result.data.action,
                            domain=result.data.domain,
                            info=result.data.info,
                            additional=result.data.additional,
                        )
                    )

        if spf_section.body:
            validation_section.add_subsection(spf_section)

        if mx_section.body:
            validation_section.add_subsection(mx_section)

        if general_sender_section.subsections:
            validation_section.add_subsection(general_sender_section)

        return validation_section

    def add_mx_records_to_multi_section(
        self, mx_section: ResultMultiSection, result: HeaderValidatorResponse, parsed_headers: EmailHeaders
    ):
        mx_kv_section = KVSectionBody()
        mx_kv_section.set_item("From/Sender domain", result.data["domain"])
        mx_kv_section.set_item("Last Received Domain (expected)", parsed_headers.received[-1].domain)
        mx_section.add_section_part(mx_kv_section)

        mx_section.add_section_part(TextSectionBody("MX record domains of From/Sender domain"))
        mx_table_section = TableSectionBody()
        for rdata in sorted(result.data["mx"], key=lambda data: int(data.preference)):
            mx_table_section.add_row(TableRow(exchange=str(rdata.exchange), preference=str(rdata.preference)))
            match = re.search(DOMAIN_REGEX, str(rdata.exchange))
            if match:
                mx_section.add_tag("network.static.domain", match.group(0))
        mx_section.add_section_part(mx_table_section)
