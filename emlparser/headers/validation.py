import re
import logging

from abc import ABC, abstractmethod
from enum import Enum, auto
from typing import List
from dataclasses import dataclass
from typing import Any, Optional

from assemblyline.odm import Email
from emlparser.headers.parser import EmailHeaders, DnsResolver

EMAIL_VALIDATOR = Email()


class HeaderValidatorResponseKind(Enum):
    MISSING_FROM = auto()
    FROM_SENDER_DIFFER = auto()
    FROM_REPLY_TO_DIFFER = auto()
    FROM_RETURN_PATH_DIFFER = auto()
    RECEIVED_HEADER_PARSING_ISSUE = auto()
    SENDER_HEADER_PARSING_ISSUE = auto()
    FROM_HEADER_PARSING_ISSUE = auto()
    EMAIL_DISPLAY_NAME_DIFFER = auto()
    MX_DOMAIN_RECORD_MISSING = auto()
    MX_DOMAIN_NOT_MATCHING = auto()
    MX_DOMAIN_FROMDOMAIN_NOT_FOUND=auto()
    MX_DOMAIN_VALID=auto()
    FAIL_SPF = auto()
    SOFTFAIL_SPF = auto()
    NONE_SPF = auto()
    NEUTRAL_SPF = auto()
    PERMERROR_SPF = auto()
    TEMPERROR_SPF = auto()
    PASS_SPF = auto()


@dataclass
class HeaderValidatorResponse:
    kind: HeaderValidatorResponseKind
    data: Optional[Any] = None


class HeaderValidator(ABC):
    @abstractmethod
    def validate(self, headers: EmailHeaders) -> List[HeaderValidatorResponse]:
        ...


class GeneralHeaderValidation(HeaderValidator):
    def validate(self, headers: EmailHeaders) -> List[HeaderValidatorResponse]:
        responses = []

        if headers._from.address == '':
            return [HeaderValidatorResponse(kind=HeaderValidatorResponseKind.MISSING_FROM)]
        if headers.sender.address and headers._from.address != headers.sender.address:
            responses.append(HeaderValidatorResponse(kind=HeaderValidatorResponseKind.FROM_SENDER_DIFFER))
        if headers.reply_to.address and headers._from.address != headers.reply_to.address:
            responses.append(HeaderValidatorResponse(kind=HeaderValidatorResponseKind.FROM_REPLY_TO_DIFFER))
        if headers.return_path.address and headers._from.address != headers.return_path.address:
            responses.append(HeaderValidatorResponse(kind=HeaderValidatorResponseKind.FROM_RETURN_PATH_DIFFER))
        if headers._from.name and (name_email := EMAIL_VALIDATOR.check(headers._from.name)) and name_email != headers._from.address:
            responses.append(HeaderValidatorResponse(kind=HeaderValidatorResponseKind.EMAIL_DISPLAY_NAME_DIFFER))

        return responses


class MxHeaderValidation(HeaderValidator):
    def __init__(self, dns_resolver: DnsResolver):
        self._dns_resolver = dns_resolver

    def validate(self, headers: EmailHeaders) -> List[HeaderValidatorResponse]:
        fromdomain = None

        match = re.search(r"(\w+\.\w+)$", headers.sender.address)
        if not match:
            logging.error("Sender header regex didn't match")
        else:
            fromdomain = match.group(1)

        if not fromdomain:
            match = re.search(r"(\w+\.\w+)$", headers._from.address)
            if not match:
                logging.error("From header regex didn't match")
            else:
                fromdomain = match.group(1)

        if not fromdomain:
            return [HeaderValidatorResponse(kind=HeaderValidatorResponseKind.MX_DOMAIN_FROMDOMAIN_NOT_FOUND)]

        mx = self._dns_resolver.query(fromdomain, 'MX')

        if not mx:
            return [HeaderValidatorResponse(kind=HeaderValidatorResponseKind.MX_DOMAIN_RECORD_MISSING, data=fromdomain)]

        for rdata in mx:
            match = re.search(r"(\w+\.\w+).$", str(rdata.exchange))
            if not match:
                print("MX domain regex didn't match")
                continue

            if headers.received[-1].domain in match.group(1):
                return [HeaderValidatorResponse(kind=HeaderValidatorResponseKind.MX_DOMAIN_VALID, data={"exchange": rdata.exchange, "domain": fromdomain, "mx": mx})]

        return [HeaderValidatorResponse(kind=HeaderValidatorResponseKind.MX_DOMAIN_NOT_MATCHING, data={"mx": mx, "domain": fromdomain})]


class SpfHeaderValidation(HeaderValidator):
    ACTION_RESULT_MAPPING = {
        'fail': HeaderValidatorResponseKind.FAIL_SPF,
        'softfail': HeaderValidatorResponseKind.SOFTFAIL_SPF,
        'none': HeaderValidatorResponseKind.NONE_SPF,
        'neutral': HeaderValidatorResponseKind.NEUTRAL_SPF,
        'permerror': HeaderValidatorResponseKind.PERMERROR_SPF,
        'temperror': HeaderValidatorResponseKind.TEMPERROR_SPF,
        'pass': HeaderValidatorResponseKind.PASS_SPF,
    }
    FAIL_RESPNSE_KINDS = [
        HeaderValidatorResponseKind.FAIL_SPF,
        HeaderValidatorResponseKind.SOFTFAIL_SPF,
    ]

    def validate(self, headers: EmailHeaders) -> List[HeaderValidatorResponse]:
        responses = []

        for received_spf in headers.received_spf:
            if (kind:= self.ACTION_RESULT_MAPPING.get(received_spf.action)) and kind not in responses:
                responses.append(HeaderValidatorResponse(kind=kind, data=received_spf))

        return responses


class SpoofValidator:
    def __init__(self, headers: EmailHeaders):
        self.headers = headers
        self.validators: List[HeaderValidator] = [
            GeneralHeaderValidation(),
            MxHeaderValidation(dns_resolver=DnsResolver()),
            SpfHeaderValidation()
        ]

    def get_validation_results(self) -> List[HeaderValidatorResponse]:
        results = []

        for validator in self.validators:
            results.extend(validator.validate(self.headers))

        return results
