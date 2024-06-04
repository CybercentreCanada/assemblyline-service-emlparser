from unittest import TestCase
from unittest.mock import MagicMock, patch
from typing import Optional, List

from emlparser.headers.parser import ReceivedSpf, Received, EmailHeaders, Sender, DnsResolver


class TestReceivedSpfParser(TestCase):
    def test_given_invalid_received_spf_when_parse_then_return_none(self):
        received_spf = "invalid received spf header"

        results = ReceivedSpf.parse(received_spf)

        self.assertIsNone(results)

    def test_given_valid_received_spf_when_parsing_then_return_extract_parts(self):
        received_spf = """    	ActionResult   (test.domain.com: more information about the reason of action) additional=kv; data=1.1.1.1;"""

        results = ReceivedSpf.parse(received_spf)

        self.assertEqual(results.action, "actionresult")
        self.assertEqual(results.domain, "test.domain.com")
        self.assertEqual(results.info, "more information about the reason of action")
        self.assertEqual(results.additional, "additional=kv; data=1.1.1.1;")


class TestReceivedParser(TestCase):
    def test_given_invalid_received_when_parsing_then_return_none(self):
        dns_resolver = DnsResolver()
        dns_resolver.reverse_ip_lookup = MagicMock(return_value=None)
        invalid_received_header = "invalid received header"

        results = Received.parse(invalid_received_header, dns_resolver)

        self.assertIsNone(results)
        dns_resolver.reverse_ip_lookup.assert_not_called()

    def test_given_invalid_domain_or_ip_in_received_when_parsing_then_return_none(self):
        dns_resolver = DnsResolver()
        dns_resolver.reverse_ip_lookup = MagicMock(return_value=None)
        invalid_received_header = """by notadomainorip"""

        results = Received.parse(invalid_received_header, dns_resolver)

        self.assertIsNone(results)
        dns_resolver.reverse_ip_lookup.assert_not_called()

    def test_given_received_with_domain_when_parsing_then_return_extracted_parts_and_do_not_perform_dns_call(self):
        dns_resolver = DnsResolver()
        dns_resolver.reverse_ip_lookup = MagicMock(return_value=None)
        invalid_received_header = """blahblah by prod.exchangelabs.com  with HTTPS; blahblah"""

        results = Received.parse(invalid_received_header, dns_resolver)

        self.assertEqual(results.domain, "exchangelabs.com")
        dns_resolver.reverse_ip_lookup.assert_not_called()

    def test_given_received_with_ip_when_parsing_then_return_extracted_parts_and_perform_dns_call(self):
        dns_resolver = DnsResolver()
        dns_resolver.reverse_ip_lookup = MagicMock(return_value="test.com")
        invalid_received_header = """blahblah by 1.1.1.1  with HTTPS; blahblah"""

        results = Received.parse(invalid_received_header, dns_resolver)

        self.assertEqual(results.domain, "test.com")
        dns_resolver.reverse_ip_lookup.assert_called_once_with("1.1.1.1")


class TestSenderParser(TestCase):
    def test_given_none_when_parsing_then_return_sender_with_empty_parts(self):
        results = Sender.parse(None)

        self.assertEqual(results.name, "")
        self.assertEqual(results.address, "")

    def test_given_only_email_address_when_parsing_then_return_sender_with_address_populated(self):
        results = Sender.parse("    email@test.com")

        self.assertEqual(results.name, "")
        self.assertEqual(results.address, "email@test.com")

    def test_given_only_email_address_with_brackets_when_parsing_then_return_sender_with_address_populated(self):
        results = Sender.parse("<email@test.com>")

        self.assertEqual(results.name, "")
        self.assertEqual(results.address, "email@test.com")

    def test_given_email_address_and_name_when_parsing_then_return_sender_with_name_and_name_populated(self):
        results = Sender.parse(" Test Name of User   <email@test.com>")

        self.assertEqual(results.name, "Test Name of User")
        self.assertEqual(results.address, "email@test.com")


class TestEmailHeaders(TestCase):
    @patch("emlparser.headers.parser.Sender.parse")
    def test_given_sender_when_parsing_then_sender_parser_called_with_sender(self, mocked_sender_parse):
        sender = "any sender data"

        self._build_email_headers(sender=sender)

        mocked_sender_parse.assert_any_call(sender)

    @patch("emlparser.headers.parser.Sender.parse")
    def test_given_from_when_parsing_then_sender_parser_called_with_from(self, mocked_sender_parse):
        _from = "any from data"

        self._build_email_headers(sender=_from)

        mocked_sender_parse.assert_any_call(_from)

    @patch("emlparser.headers.parser.Sender.parse")
    def test_given_reply_to_when_parsing_then_sender_parser_called_with_reply_to(self, mocked_sender_parse):
        reply_to = "any reply_to data"

        self._build_email_headers(sender=reply_to)

        mocked_sender_parse.assert_any_call(reply_to)

    @patch("emlparser.headers.parser.Sender.parse")
    def test_given_return_path_when_parsing_then_sender_parser_called_with_return_path(self, mocked_sender_parse):
        return_path = "any return_path data"

        self._build_email_headers(sender=return_path)

        mocked_sender_parse.assert_any_call(return_path)

    @patch("emlparser.headers.parser.ReceivedSpf.parse")
    def test_given_received_spf_when_parsing_then_received_spf_parser_called_n_times_with_received_spf_data(self, mocked_sender_parse):
        received_spf = [
            "any received_spf data",
            "another different received_spf data"
        ]

        self._build_email_headers(received_spf=received_spf)

        mocked_sender_parse.assert_any_call(received_spf[0])
        mocked_sender_parse.assert_any_call(received_spf[1])

    @patch("emlparser.headers.parser.Received.parse")
    def test_given_received_when_parsing_then_received_parser_called_n_times_with_received_data(self, mocked_sender_parse):
        received = [
            "any received data",
            "another different received data"
        ]
        dns_resolver = DnsResolver()

        self._build_email_headers(received=received, dns_resolver=dns_resolver)

        mocked_sender_parse.assert_any_call(received[0], dns_resolver)
        mocked_sender_parse.assert_any_call(received[1], dns_resolver)

    def _build_email_headers(
        self,
        sender: Optional[str] = None,
        _from: Optional[str] = None,
        reply_to: Optional[str] = None,
        return_path: Optional[str] = None,
        received: Optional[List[str]] = None,
        received_spf: Optional[List[str]] = None,
        dns_resolver: Optional[DnsResolver] = None,
    ):
        return EmailHeaders(
            sender=sender,
            _from=_from,
            reply_to=reply_to,
            return_path=return_path,
            received=received,
            received_spf=received_spf,
            dns_resolver=dns_resolver or DnsResolver()
        )
