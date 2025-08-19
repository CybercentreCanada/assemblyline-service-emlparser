from unittest import TestCase
from unittest.mock import MagicMock
from typing import List
from dataclasses import dataclass

from emlparser.headers.parser import EmailHeaders, DnsResolver
from emlparser.headers.validation import GeneralHeaderValidation, HeaderValidatorResponse, HeaderValidatorResponseKind, SpfHeaderValidation, MxHeaderValidation


_any_subject = "A test subject"
_any_email_address = "test@email.address"
_any_received = """from ID.prod.exchangelabs.com (2000:1000:500:f7::10) by
 ID2.prod.exchangelabs.com with HTTPS; Sun, 20 Aug 2023 06:50:56
 +0000"""
_fail_received_spf = """Fail (protection.outlook.com: domain of redacted.co.com does
 not designate 88.99.11.22 as permitted sender)
 receiver=protection.outlook.com; client-ip=11.22.33.11;
 helo=redacted.co.com;"""
_softfail_received_spf = """SoftFail (protection.outlook.com: domain of transitioning
 newsletters.cbc.ca discourages use of 44.33.66.123 as permitted sender)"""
_none_received_spf = """None (protection.outlook.com: redacted.net does not designate
 permitted sender hosts)"""
_neutral_received_spf = """Neutral (ETC-PAR-2.canada.net.pk: 111.123.77.22 is neither
 permitted nor denied by domain of info@redacted.com)"""
_permerror_received_spf = """PermError (protection.outlook.com: domain of
 redacted.com used an invalid SPF mechanism)"""
_temperror_received_spf = """TempError (protection.outlook.com: error in processing during
 lookup of redacted.ca: DNS Timeout)"""
_pass_received_spf = """pass (google.com: domain of return@redacted.ca designates 13.2.31.1 as permitted sender) client-ip=13.2.31.1;"""


@dataclass
class MxRdataTestCls:
    exchange: str


def _build_email_headers(
    subject: str = _any_subject,
    sender: str = _any_email_address,
    _from: str = _any_email_address,
    reply_to: str = _any_email_address,
    return_path: str = _any_email_address,
    received: List[str] = None,
    received_spf: List[str] = None,
    authentication_results: List[str] = None,
    dns_resolver: DnsResolver = None,
) -> EmailHeaders:
    return EmailHeaders(
        subject=subject,
        sender=sender,
        _from=_from,
        reply_to=reply_to,
        return_path=return_path,
        received=received or [],
        received_spf=received_spf or [],
        authentication_results=authentication_results,
        dns_resolver=dns_resolver or DnsResolver(),
    )


def assert_kind_in_responses(kind: HeaderValidatorResponseKind, responses: List[HeaderValidatorResponse]):
    response_kinds = [response.kind for response in responses]
    assert kind in response_kinds


def assert_kind_not_in_responses(kind: HeaderValidatorResponseKind, responses: List[HeaderValidatorResponse]):
    response_kinds = [response.kind for response in responses]
    assert kind not in response_kinds


class TestGeneralHeaderValidation(TestCase):
    def test_given_valid_headers_when_calling_validate_then_results_is_empty(self):
        headers = _build_email_headers()

        results = GeneralHeaderValidation().validate(headers=headers)

        self.assertEqual(results, [])

    def test_given_no_from_address_when_calling_validate_then_results_contains_missing_from_response(self):
        headers = _build_email_headers(_from="")

        results = GeneralHeaderValidation().validate(headers=headers)

        assert_kind_in_responses(HeaderValidatorResponseKind.MISSING_FROM, results)

    def test_given_differing_sender_and_recipient_when_calling_validate_then_results_contains_from_sender_differ_response(self):
        headers = _build_email_headers(sender="different@email.address")

        results = GeneralHeaderValidation().validate(headers=headers)

        assert_kind_in_responses(HeaderValidatorResponseKind.FROM_SENDER_DIFFER, results)

    def test_given_differing_reply_to_and_recipient_when_calling_validate_then_results_contains_from_reply_to_differ_response(self):
        headers = _build_email_headers(reply_to="different@email.address")

        results = GeneralHeaderValidation().validate(headers=headers)

        assert_kind_in_responses(HeaderValidatorResponseKind.FROM_REPLY_TO_DIFFER, results)

    def test_given_differing_return_path_and_recipient_when_calling_validate_then_results_contains_from_return_path_differ_response(self):
        headers = _build_email_headers(return_path="different@email.address")

        results = GeneralHeaderValidation().validate(headers=headers)

        assert_kind_in_responses(HeaderValidatorResponseKind.FROM_RETURN_PATH_DIFFER, results)

    def test_given_differ_display_name_and_email_within_from_header_when_calling_validate_then_results_contains_email_display_name_differ_response(self):
        headers = _build_email_headers(_from="test@spoof.ca <test@real.ca>")

        results = GeneralHeaderValidation().validate(headers=headers)

        assert_kind_in_responses(HeaderValidatorResponseKind.EMAIL_DISPLAY_NAME_DIFFER, results)

    def test_given_differ_display_name_is_not_an_email_within_from_header_when_calling_validate_then_results_does_not_contain_email_display_name_differ_response(self):
        headers = _build_email_headers(_from='	"Leo Opitz" <buero@julestois.com>')

        results = GeneralHeaderValidation().validate(headers=headers)

        assert_kind_not_in_responses(HeaderValidatorResponseKind.EMAIL_DISPLAY_NAME_DIFFER, results)

    def test_given_all_are_different_when_calling_validate_then_results_contains_all_responses(self):
        headers = _build_email_headers(
            sender="sender@email.address",
            reply_to="reply.to@email.address",
            return_path="return.path@email.address"
        )

        results = GeneralHeaderValidation().validate(headers=headers)

        assert_kind_in_responses(HeaderValidatorResponseKind.FROM_SENDER_DIFFER, results)
        assert_kind_in_responses(HeaderValidatorResponseKind.FROM_REPLY_TO_DIFFER, results)
        assert_kind_in_responses(HeaderValidatorResponseKind.FROM_RETURN_PATH_DIFFER, results)

class TestSpfHeaderValidation(TestCase):
    def test_given_no_received_spf_when_calling_validate_then_results_is_empty(self):
        headers = _build_email_headers(received_spf=[])

        results = SpfHeaderValidation().validate(headers=headers)

        self.assertEqual(results, [])

    def test_given_fail_received_spf_when_calling_validate_then_results_contains_fail_spf_response(self):
        headers = _build_email_headers(received_spf=[_fail_received_spf])

        results = SpfHeaderValidation().validate(headers=headers)

        assert_kind_in_responses(HeaderValidatorResponseKind.FAIL_SPF, results)


    def test_given_softfail_received_spf_when_calling_validate_then_results_contains_softfail_spf_response(self):
        headers = _build_email_headers(received_spf=[_softfail_received_spf])

        results = SpfHeaderValidation().validate(headers=headers)

        assert_kind_in_responses(HeaderValidatorResponseKind.SOFTFAIL_SPF, results)

    def test_given_none_received_spf_when_calling_validate_then_results_contains_none_spf_response(self):
        headers = _build_email_headers(received_spf=[_none_received_spf])

        results = SpfHeaderValidation().validate(headers=headers)

        assert_kind_in_responses(HeaderValidatorResponseKind.NONE_SPF, results)

    def test_given_neutral_received_spf_when_calling_validate_then_results_contains_neutral_spf_response(self):
        headers = _build_email_headers(received_spf=[_neutral_received_spf])

        results = SpfHeaderValidation().validate(headers=headers)

        assert_kind_in_responses(HeaderValidatorResponseKind.NEUTRAL_SPF, results)

    def test_given_permerror_received_spf_when_calling_validate_then_results_contains_permerror_spf_response(self):
        headers = _build_email_headers(received_spf=[_permerror_received_spf])

        results = SpfHeaderValidation().validate(headers=headers)

        assert_kind_in_responses(HeaderValidatorResponseKind.PERMERROR_SPF, results)

    def test_given_temperror_received_spf_when_calling_validate_then_results_contains_temperror_spf_response(self):
        headers = _build_email_headers(received_spf=[_temperror_received_spf])

        results = SpfHeaderValidation().validate(headers=headers)

        assert_kind_in_responses(HeaderValidatorResponseKind.TEMPERROR_SPF, results)

    def test_given_pass_received_spf_when_calling_validate_then_results_contains_pass_spf_response(self):
        headers = _build_email_headers(received_spf=[_pass_received_spf])

        results = SpfHeaderValidation().validate(headers=headers)

        assert_kind_in_responses(HeaderValidatorResponseKind.PASS_SPF, results)

    def test_given_multiple_received_spf_when_calling_validate_then_results_contains_multiple_responses(self):
        headers = _build_email_headers(received_spf=[_pass_received_spf, _softfail_received_spf, _permerror_received_spf, _none_received_spf])

        results = SpfHeaderValidation().validate(headers=headers)

        assert_kind_in_responses(HeaderValidatorResponseKind.PASS_SPF, results)
        assert_kind_in_responses(HeaderValidatorResponseKind.SOFTFAIL_SPF, results)
        assert_kind_in_responses(HeaderValidatorResponseKind.PERMERROR_SPF, results)
        assert_kind_in_responses(HeaderValidatorResponseKind.NONE_SPF, results)


class TestMxHeaderValidation(TestCase):
    def test_given_empty_sender_and_from_when_calling_validate_then_results_contains_fromdomain_not_found(self):
        dns_resolver = DnsResolver()
        dns_resolver.query = MagicMock(return_value=None)
        headers = _build_email_headers(received=[_any_received], sender="", _from="")

        results = MxHeaderValidation(dns_resolver=DnsResolver()).validate(headers)

        assert_kind_in_responses(HeaderValidatorResponseKind.MX_DOMAIN_FROMDOMAIN_NOT_FOUND, results)
        dns_resolver.query.assert_not_called()

    def test_given_valid_sender_when_calling_validate_then_results_contains_mx_domain_record_missing(self):
        dns_resolver = DnsResolver()
        dns_resolver.query = MagicMock(return_value=None)
        headers = _build_email_headers(received=[_any_received], sender="sender@test.com")

        results = MxHeaderValidation(dns_resolver=dns_resolver).validate(headers)

        assert_kind_in_responses(HeaderValidatorResponseKind.MX_DOMAIN_RECORD_MISSING, results)
        self.assertEqual(results[0].data, "test.com")
        dns_resolver.query.assert_called_once_with("test.com", "MX")

    def test_given_valid_sender_and_non_matching_mx_records_calling_validate_then_results_contains_not_matching_mx_domain(self):
        query_response = [MxRdataTestCls(exchange="test.com.")]
        dns_resolver = DnsResolver()
        dns_resolver.query = MagicMock(return_value=query_response)
        headers = _build_email_headers(received=[_any_received], sender="sender@test.com")

        results = MxHeaderValidation(dns_resolver=dns_resolver).validate(headers)

        assert_kind_in_responses(HeaderValidatorResponseKind.MX_DOMAIN_NOT_MATCHING, results)
        self.assertEqual(results[0].data["mx"], query_response)
        self.assertEqual(results[0].data["domain"], "test.com")
        dns_resolver.query.assert_called_once_with("test.com", "MX")

    def test_given_valid_from_and_mx_records_calling_validate_then_results_contains_valid_mx_domain(self):
        query_response = [MxRdataTestCls(exchange="exchangelabs.com.")]
        dns_resolver = DnsResolver()
        dns_resolver.query = MagicMock(return_value=query_response)
        headers = _build_email_headers(received=[_any_received], sender="", _from="from@example.com")

        results = MxHeaderValidation(dns_resolver=dns_resolver).validate(headers)

        assert_kind_in_responses(HeaderValidatorResponseKind.MX_DOMAIN_VALID, results)
        self.assertEqual(results[0].data["mx"], query_response)
        self.assertEqual(results[0].data["domain"], "example.com")
        self.assertEqual(results[0].data["exchange"], "exchangelabs.com.")
        dns_resolver.query.assert_called_once_with("example.com", "MX")
