import base64
import email
import json
import os
import re
import shutil
import tempfile
import traceback
from datetime import datetime
from hashlib import sha256
from ipaddress import IPv4Address, ip_address
from urllib.parse import urlparse

import eml_parser
import extract_msg
from assemblyline.common import forge
from assemblyline.common.str_utils import safe_str
from assemblyline.odm import DOMAIN_ONLY_REGEX, EMAIL_REGEX, FULL_URI, IP_ONLY_REGEX, IP_REGEX
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import BODY_FORMAT, Result, ResultKeyValueSection, ResultSection
from assemblyline_v4_service.common.task import MaxExtractedExceeded
from assemblyline_v4_service.common.utils import extract_passwords
from bs4 import BeautifulSoup, Comment
from mailparser.utils import msgconvert
from multidecoder.decoders.network import EMAIL_RE, find_domains, find_emails, find_ips, find_urls

from emlparser.outlookmsgfile import load as msg2eml

NETWORK_IOC_TYPES = ["uri", "email", "domain"]
IDENTIFY = forge.get_identify(use_cache=os.environ.get("PRIVILEGED", "false").lower() == "true")


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
            msg: extract_msg.msg_classes.msg.MSGFile = extract_msg.openMsg(
                request.file_path,
                overrideEncoding=overrideEncoding,
                errorBehavior=extract_msg.enums.ErrorBehavior.SUPPRESS_ALL,
            )
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
        ) as e1:
            if isinstance(e1, UnicodeDecodeError) and overrideEncoding is None:
                previous_string_encoding = msg.stringEncoding
                msg = self.get_outlook_msg(request, overrideEncoding="cp1252")
                msg.recipients
                if msg:
                    ResultSection(
                        "Wrong String Encoding Stored",
                        parent=request.result,
                        body=(
                            f"String encoding {previous_string_encoding} was specified in outlook file, "
                            "but cp1252 was needed."
                        ),
                    )
                return msg

            if isinstance(e1, OSError) and str(e1) != "incomplete OLE sector":
                raise

            if isinstance(e1, IndexError) and str(e1) == "tuple index out of range":
                tb = traceback.format_exc()
                # Found some very corrupted MessageSigned that are triggering this error with attachments
                # We'll just extract the information we can as an eml if it is the case
                if "entry['guid'] = guids[entry['guid_index']]" not in tb:
                    raise

            # If we can't use extract-msg, rely on converting to eml
            self.log.warning(e1, exc_info=True)
            try:
                content_str = msg2eml(request.file_path).as_bytes()
            except Exception as e2:
                self.log.warning(e2, exc_info=True)
                # Try using mailparser to convert
                converted_path, _ = msgconvert(request.file_path)
                with open(converted_path, "rb") as f:
                    content_str = f.read()
            self.handle_eml(request, content_str)

    def handle_outlook(self, request: ServiceRequest) -> None:
        msg: extract_msg.msg_classes.msg.MSGFile = self.get_outlook_msg(request)
        if msg is None:
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
                        f"attachment{'s' if len(attachments) > 1 else ''} were processed instead."
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
                    try:
                        document = open(attachment_path, encoding="UTF-8").read()
                    except UnicodeDecodeError:
                        document = open(attachment_path, encoding="cp1252").read()

                    # Check to see if there's any "defang_" prefixed tags
                    # Reference: https://github.com/robmueller/html-defang
                    if "<!--defang_" not in document:
                        break

                    # Find all comments
                    enable_brackets = True
                    for i in BeautifulSoup(document).find_all(string=lambda t: isinstance(t, Comment)):
                        if "*SC*" in i:
                            # Ignore comments with these lines
                            continue
                        defanged_i = i.replace("defang_", "")
                        if enable_brackets:
                            defanged_i = f"<{defanged_i}>"
                        else:
                            defanged_i = f"{defanged_i}"

                        if defanged_i == "<script>":
                            enable_brackets = False
                        elif defanged_i == "/script":
                            enable_brackets = True
                            defanged_i = f"<{defanged_i}>"

                        document = document.replace(f"<!--{i}-->", defanged_i)
                    # Strip "defang_" from any remaining defanged-prefixed tags that weren't commented
                    document = document.replace("defang_", "")
                    refanged_fp = os.path.join(self.working_directory, f"{attachment_name}_refanged.html")
                    with open(refanged_fp, "w") as fp:
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
                for address_field in [b"\nTo:", b"\nCC:", b"\nFrom:"]:
                    if address_field not in content_str:
                        continue
                    to_start_index = content_str.index(address_field)
                    to_end_index = re.search(rb"\n\S", content_str[to_start_index + len(address_field) :]).start()
                    content_str = (
                        content_str[:to_start_index]
                        + content_str[to_start_index : to_start_index + len(address_field) + to_end_index]
                        .replace(b"=0D", b"")
                        .replace(b"=0A", b"")
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

        all_iocs = {}
        [all_iocs.setdefault(t, set()) for t in NETWORK_IOC_TYPES]
        if "from" in header or "to" in header or parsed_eml.get("attachments"):
            body_words = set(extract_passwords(header["subject"]))
            for body_counter, body in enumerate(parsed_eml["body"]):
                body_text = BeautifulSoup(body["content"]).text
                body_words.update(extract_passwords(body_text))
                if request.get_param("extract_body_text"):
                    fd, path = tempfile.mkstemp(dir=self.working_directory)
                    with open(path, "w") as f:
                        f.write(body["content"])
                        os.close(fd)
                    request.add_extracted(path, "body_" + str(body_counter), "Body text")
                for ioc_type in NETWORK_IOC_TYPES:
                    all_iocs[ioc_type] = all_iocs[ioc_type].union(set(body.get(ioc_type, [])))
            # Words in the email body, used by extract to guess passwords
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
            if all_iocs["uri"]:
                uri_section = ResultSection("URIs Found:", parent=request.result)
                for uri in sorted(all_iocs["uri"]):
                    for invalid_uri_char in ['"', "'", "<", ">"]:
                        for u in uri.split(invalid_uri_char):
                            if re.match(FULL_URI, u):
                                uri = u
                                break
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
            # If we've found domains, add them to a section
            if all_iocs["domain"]:
                domain_section = ResultSection("Domains Found:")
                for domain in sorted(all_iocs["domain"]):
                    if not re.match(DOMAIN_ONLY_REGEX, domain):
                        continue
                    domain_section.add_line(domain)
                    domain_section.add_tag("network.static.domain", domain)
                if domain_section.body:
                    request.result.add_section(domain_section)
            # If we've found email addresses, add them to a section
            if all_iocs["email"]:
                email_section = ResultSection("Email Addresses Found:")
                for eml_adr in sorted(all_iocs["email"]):
                    if not re.match(EMAIL_REGEX, eml_adr):
                        continue
                    email_section.add_line(eml_adr)
                    email_section.add_tag("network.email.address", eml_adr)
                if email_section.body:
                    request.result.add_section(email_section)

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
                persisted_urls_block = (
                    "".join(
                        [
                            header[f"x-ms-exchange-organization-persisted-urls-{i}"][0]
                            for i in range(int(header["x-ms-exchange-organization-persisted-urls-chunkcount"][0]))
                        ]
                    )
                    .strip()
                    .encode()
                )

                # Look for network IOCs in this block and tag them
                [kv_section.add_tag("network.static.domain", x.value) for x in find_domains(persisted_urls_block)]
                [kv_section.add_tag("network.static.ip", x.value) for x in find_ips(persisted_urls_block)]
                [kv_section.add_tag("network.static.uri", x.value) for x in find_urls(persisted_urls_block)]

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
                            "Extract limit reached on attachments: "
                            f"{len(attachment) - len(attachments_added)} not added"
                        )
                        break
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

        else:
            self.log.warning("emlParser could not parse EML; no useful information in result's headers")
