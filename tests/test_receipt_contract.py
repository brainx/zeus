from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from zeus.message_store import _ERROR_CODES, _RUN_STATES, MAX_MESSAGE_RECEIPTS, MessageStore
from zeus.receipt_api import receipt_response
from zeus.state import StateStore


class ReceiptContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.spec = json.loads(Path("docs/openapi.json").read_text(encoding="utf-8"))
        self.schemas = self.spec["components"]["schemas"]

    def test_receipt_operations_document_auth_errors_and_fixed_response_shapes(self) -> None:
        for path, operation_id, schema in (
            ("/messages", "listMessageReceipts", "MessageReceiptPage"),
            ("/messages/{message_id}", "getMessageReceipt", "MessageReceipt"),
            ("/messages/capacity", "getMessageCapacity", "MessageCapacity"),
        ):
            with self.subTest(path=path):
                self.assertEqual({"get"}, set(self.spec["paths"][path]))
                operation = self.spec["paths"][path]["get"]
                self.assertEqual(operation_id, operation["operationId"])
                self.assertEqual("observer", operation["x-zeus-permission"])
                self.assertEqual([{"ZeusApiKey": []}], operation["security"])
                self.assertTrue(
                    {"200", "400", "401", "403", "429", "500", "503"}
                    <= operation["responses"].keys()
                )
                self.assertEqual(
                    "#/components/schemas/" + schema,
                    operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
                )
                for response in operation["responses"].values():
                    self.assertEqual(
                        {"$ref": "#/components/headers/XRequestID"},
                        response["headers"]["X-Request-ID"],
                    )
                    self.assertEqual(
                        {"$ref": "#/components/headers/CacheControl"},
                        response["headers"]["Cache-Control"],
                    )
        detail = self.spec["paths"]["/messages/{message_id}"]["get"]
        self.assertIn("unknown_message", detail["responses"]["404"]["description"])
        capacity = self.spec["paths"]["/messages/capacity"]["get"]
        self.assertEqual([], capacity["parameters"])
        self.assertIn("message_read_budget_exceeded", capacity["responses"]["503"]["description"])

    def test_pagination_identifier_and_stored_enums_match_runtime_boundaries(self) -> None:
        parameters = {
            parameter["name"]: parameter
            for parameter in self.spec["paths"]["/messages"]["get"]["parameters"]
        }
        self.assertEqual({"bot_id", "limit", "before"}, set(parameters))
        self.assertEqual(
            {"type": "integer", "minimum": 1, "maximum": 100, "default": 50},
            parameters["limit"]["schema"],
        )
        before = parameters["before"]["schema"]
        self.assertEqual("^[0-9a-f]{32}$", before["pattern"])
        self.assertEqual((32, 32), (before["minLength"], before["maxLength"]))
        detail_id = self.spec["paths"]["/messages/{message_id}"]["get"]["parameters"][0]
        self.assertEqual(before, detail_id["schema"])
        page = self.schemas["MessageReceiptPage"]["properties"]
        self.assertEqual(100, page["items"]["maxItems"])
        self.assertEqual(["string", "null"], page["next_before"]["type"])
        receipt = self.schemas["MessageReceipt"]["properties"]
        self.assertEqual(
            {"unknown", "accepted", "rejected"}, set(receipt["dispatch_state"]["enum"])
        )
        self.assertEqual(_RUN_STATES | {None}, set(receipt["run_status"]["enum"]))
        self.assertEqual(_ERROR_CODES | {None}, set(receipt["error_code"]["enum"]))
        self.assertEqual(
            MAX_MESSAGE_RECEIPTS,
            self.schemas["MessageCapacity"]["properties"]["limit"]["const"],
        )

    def test_documented_allowlists_match_actual_durable_observations(self) -> None:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        path = root / "zeus.db"
        StateStore(path).init()
        now = datetime(2026, 1, 1, tzinfo=UTC)
        receipt, _ = MessageStore(path).prepare(
            bot_id="coder",
            incarnation=now - timedelta(days=1),
            target_fingerprint="1" * 64,
            endpoint="http://127.0.0.1:8765/health",
            credential_fingerprint="2" * 64,
            input_fingerprint="3" * 64,
            request_key_fingerprint=None,
            now=now,
            retry_before=now + timedelta(minutes=10),
        )
        for target, schema_name in (
            ("/messages/" + receipt.message_id, "MessageReceipt"),
            ("/messages", "MessageReceiptPage"),
            ("/messages/capacity", "MessageCapacity"),
        ):
            with self.subTest(target=target):
                status, body = receipt_response(target, target, path)
                self.assertEqual(200, status)
                schema = self.schemas[schema_name]
                self.assertFalse(schema["additionalProperties"])
                self.assertEqual(set(body), set(schema["required"]))
                self.assertEqual(set(body), set(schema["properties"]))
                for name, value in body.items():
                    definition = schema["properties"][name]
                    if "enum" in definition:
                        self.assertIn(value, definition["enum"])
                    if value is None:
                        self.assertIn("null", definition["type"])
        receipt_properties = self.schemas["MessageReceipt"]["properties"]
        for excluded in (
            "endpoint",
            "request_hash",
            "upstream_key",
            "request_key_hash",
            "credential_fingerprint",
            "target_fingerprint",
            "lease_until",
            "version",
        ):
            self.assertNotIn(excluded, receipt_properties)


if __name__ == "__main__":
    unittest.main()
