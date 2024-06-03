import sys
import email
import re
import logging

import dns.resolver
import dns.reversename

from email.utils import parseaddr
from typing import List, Optional, Union
from dataclasses import dataclass


@dataclass
class ReceivedSpf:
    domain: str
    action: str
    info: str
    additional: str

    @staticmethod
    def parse(raw_received_spf: str) -> Optional["ReceivedSpf"]:
        match = re.search(r"\s*(\w+)\s+\((.*?):\s*(.*?)\)\s*(.*);?", _string_clean(raw_received_spf))

        if not match:
            logging.error("Received-Spf header regex didn't match")
            return None

        return ReceivedSpf(
            domain=match.group(2),
            action=match.group(1).lower(),
            info=match.group(3),
            additional=match.group(4),
        )


@dataclass
class Received:
    domain: str

    @staticmethod
    def parse(raw_received: str) -> Optional["Received"]:
        match = re.search(r"by\s+(\S*?)(?:\s+\(.*?\))?\s+", raw_received)
        if not match:
            logging.error("Received header regex didn't match")
            return None

        byname = match.group(1)
        match = re.search(r"(\w+\.\w+|\d+\.\d+\.\d+\.\d+)$", byname)
        if not match:
            logging.error("Could not find domain or IP in Received by field")
            return None

        bydomain = match.group(1)
        match = re.search(r"\.\d+$", bydomain)
        if match:
            bydomain = str(dns.reversename.from_address(bydomain)).strip('.')

        return Received(
            domain=bydomain,
        )


class EmailHeaders:
    def __init__(
        self,
        sender: Optional[str],
        _from: Optional[str],
        reply_to: Optional[str],
        return_path: Optional[str],
        received: Optional[List[str]],
        received_spf: Optional[List[str]]
    ):
        self.sender = Sender.from_str(sender)
        self._from = Sender.from_str(_from)
        self.reply_to = Sender.from_str(reply_to)
        self.return_path = Sender.from_str(return_path)

        self.received_spf: List[ReceivedSpf] = []
        for raw in (received_spf or []):
            if parsed := ReceivedSpf.parse(raw):
                self.received_spf.append(parsed)

        self.received: List[Received] = []
        for raw in (received or []):
            if parsed := Received.parse(raw):
                self.received.append(parsed)

@dataclass
class Sender:
    name: str
    address: str

    @staticmethod
    def from_str(data: Optional[str]) -> "Sender":
        (name, address) = parseaddr(_string_clean(data))

        return Sender(
            name=name,
            address=address
        )


# https://github.com/viper-framework/viper-modules/blob/00ee6cd2b2ad4ed278279ca9e383e48bc23a2555/emailparse.py#L39
def _string_clean(value: Union[str | bytes | email.header.Header | None]) -> str:
    if value:
        if isinstance(value, bytes):
            if sys.version_info < (3, 4):
                value = value.decode('utf-8', 'ignore')
            else:
                value = value.decode('utf-8', 'backslashreplace')
        elif isinstance(value, email.header.Header):
            value = str(value)
        return re.sub('[\n\t\r]', '', str(value))
    return ""
