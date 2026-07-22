from __future__ import annotations

import unittest

from zeus.api_request import decode_json_object, normalize_api_path, parse_query


class ApiPathTests(unittest.TestCase):
    def test_normalizes_only_the_v1_alias(self) -> None:
        cases = (
            ("/v1", "/"),
            ("/v1/", "/"),
            ("/v1/bots", "/bots"),
            ("/health", "/health"),
            ("/v10/bots", "/v10/bots"),
        )

        for target, expected in cases:
            with self.subTest(target=target):
                self.assertEqual(expected, normalize_api_path(target))

    def test_rejects_request_target_fragments(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            "^request target must not include a fragment$",
        ):
            normalize_api_path("/health#internal")


class ApiQueryTests(unittest.TestCase):
    def test_preserves_blank_values_and_field_order(self) -> None:
        values = parse_query(
            "/bots?second=2&first=",
            frozenset({"first", "second"}),
        )

        self.assertEqual(["second", "first"], list(values))
        self.assertEqual({"second": ["2"], "first": [""]}, values)

    def test_accepts_sixteen_query_fields(self) -> None:
        names = tuple(f"field{index}" for index in range(16))
        query = "&".join(f"{name}=1" for name in names)

        values = parse_query(f"/health?{query}", frozenset(names))

        self.assertEqual(16, len(values))

    def test_rejects_seventeen_query_fields(self) -> None:
        names = tuple(f"field{index}" for index in range(17))
        query = "&".join(f"{name}=1" for name in names)

        with self.assertRaisesRegex(ValueError, "^too many query parameters$"):
            parse_query(f"/health?{query}", frozenset(names))

    def test_reports_unknown_field_before_duplicate_field(self) -> None:
        with self.assertRaisesRegex(ValueError, "^unknown query parameter: debug$"):
            parse_query(
                "/health?known=1&known=2&debug=1",
                frozenset({"known"}),
            )

    def test_rejects_duplicate_fields(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            "^query parameter replace must be specified once$",
        ):
            parse_query(
                "/bots?replace=0&replace=1",
                frozenset({"replace"}),
            )


class ApiJsonTests(unittest.TestCase):
    def test_decodes_a_json_object(self) -> None:
        self.assertEqual(
            {"bot_id": "coder", "env": {"MODE": "safe"}},
            decode_json_object(b'{"bot_id":"coder","env":{"MODE":"safe"}}'),
        )

    def test_rejects_duplicate_fields_at_every_object_depth(self) -> None:
        cases = (
            (b'{"bot_id":"coder","bot_id":"other"}', "bot_id"),
            (b'{"env":{"MODE":"safe","MODE":"unsafe"}}', "MODE"),
        )

        for data, field in cases:
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(
                    ValueError,
                    f"^duplicate JSON field: {field}$",
                ),
            ):
                decode_json_object(data)

    def test_rejects_nonstandard_json_constants(self) -> None:
        for constant in ("NaN", "Infinity", "-Infinity"):
            with (
                self.subTest(constant=constant),
                self.assertRaisesRegex(
                    ValueError,
                    f"^invalid JSON constant: {constant}$",
                ),
            ):
                decode_json_object(f'{{"value":{constant}}}'.encode())

    def test_rejects_array_and_scalar_roots(self) -> None:
        for data in (b"[]", b'"value"', b"1", b"null"):
            with (
                self.subTest(data=data),
                self.assertRaisesRegex(
                    ValueError,
                    "^request body must be a JSON object$",
                ),
            ):
                decode_json_object(data)

    def test_accepts_and_rejects_exact_depth_boundary(self) -> None:
        data = b'{"nested":[0]}'

        self.assertEqual({"nested": [0]}, decode_json_object(data, max_depth=3))
        with self.assertRaisesRegex(ValueError, "^request JSON nesting exceeds 2$"):
            decode_json_object(data, max_depth=2)


if __name__ == "__main__":
    unittest.main()
