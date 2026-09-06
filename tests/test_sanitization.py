from __future__ import annotations

import unittest

from zeus.sanitization import redact_secrets, sanitize_text


class SecretAssignmentTests(unittest.TestCase):
    def test_secret_assignments_preserve_names_and_separators(self) -> None:
        for source, expected in (
            ("API_KEY=example", "API_KEY=[redacted]"),
            ('"api-key" : "quoted value"', '"api-key" : [redacted]'),
            ("'access_token'='it\\'s secret'", "'access_token'=[redacted]"),
            ("db.password = value, safe=yes", "db.password = [redacted], safe=yes"),
            ("prefixSECRETtail: value", "prefixSECRETtail: [redacted]"),
            ('prefix"token"="example-value"', 'prefix"token"=[redacted]'),
            ("prefix'password'=example-value", "prefix'password'=[redacted]"),
            ("to\u212aen=value", "to\u212aen=[redacted]"),
            ("password=", "password="),
            ("safe=value", "safe=value"),
        ):
            with self.subTest(source=source):
                self.assertEqual(expected, redact_secrets(source))

    def test_secret_inside_nonsecret_value_is_still_redacted(self) -> None:
        self.assertEqual(
            'message="TOKEN=[redacted] safe=value"',
            redact_secrets('message="TOKEN=example safe=value"'),
        )
        self.assertEqual(
            "outer=inner=password=[redacted]",
            redact_secrets("outer=inner=password=example"),
        )

    def test_nested_secret_assignments_are_consumed_once(self) -> None:
        self.assertEqual(
            'token=[redacted], "password": [redacted]',
            redact_secrets('token="password=example", "password": "another"'),
        )

    def test_long_plain_identifier_and_key_keep_redaction_at_end(self) -> None:
        identifier = "A" * 16_000
        text = f"{identifier} safe=value {identifier}_TOKEN=example"
        expected = f"{identifier} safe=value {identifier}_TOKEN=[redacted]"
        self.assertEqual(expected, sanitize_text(text, max_length=len(text) + 20))
        self.assertEqual(identifier, redact_secrets(identifier))


if __name__ == "__main__":
    unittest.main()
