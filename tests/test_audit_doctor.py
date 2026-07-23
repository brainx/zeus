from __future__ import annotations

import unittest


class AuditDoctorContractTests(unittest.TestCase):
    def test_doctor_report_has_machine_and_human_rendering(self) -> None:
        from zeus.audit_doctor import AuditDoctorReport

        report = AuditDoctorReport(checks=())
        self.assertEqual("", report.to_text())
        self.assertEqual({"checks": [], "ok": True}, report.to_dict())


if __name__ == "__main__":
    unittest.main()
