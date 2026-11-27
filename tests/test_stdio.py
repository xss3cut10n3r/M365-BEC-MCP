"""Exercise the native server."""

import csv
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from zipfile import ZipFile

BINARY = str(Path(sys.argv.pop(1)).resolve())


def request(method, params=None):
    return {"method": method, "params": params or {}}


def tool(name, **args):
    return request("tools/call", {"name": name, "arguments": args})


def exchange(options, *requests):
    frames = [
        {"jsonrpc": "2.0", "id": 0, **request("initialize", {
            "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}
        })},
        {"jsonrpc": "2.0", **request("notifications/initialized")},
    ]
    frames.extend({"jsonrpc": "2.0", "id": index, **msg} for index, msg in enumerate(requests, 1))
    run = subprocess.run([BINARY, *map(str, options)], text=True, encoding="utf-8",
                         input="".join(json.dumps(frame) + "\n" for frame in frames),
                         capture_output=True, timeout=45)
    if run.returncode:
        raise AssertionError(run.stderr or run.returncode)
    responses = [json.loads(line) for line in run.stdout.splitlines()]
    assert [reply["id"] for reply in responses] == list(range(len(requests) + 1))
    assert responses[0]["result"]["protocolVersion"] == "2025-11-25"
    return [reply["result"] for reply in responses[1:]]


def data(result):
    assert not result["isError"], result
    assert result["structuredContent"] == json.loads(result["content"][0]["text"])
    return result["structuredContent"]


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.signins = self.root / "InteractiveSignIns.csv"
        with self.signins.open("w", newline="", encoding="utf-8") as out:
            writer = csv.writer(out)
            writer.writerow(["Date (UTC)", "Username", "Request ID", "IP address", "Status", "Device ID"])
            writer.writerow(["2026-01-01T12:00:00Z", "user@example.org", "r1", "192.0.2.8", "Success", "d1"])
        self.audit = self.root / "audit.json"
        self.audit.write_text(json.dumps([{
            "CreationTime": "2026-01-02T00:00:00Z", "Operation": "Send", "UserId": "user@example.org",
            "Item": {"Subject": "Synthetic invoice"}, "AttachmentCount": 0, "Flag": False
        }]), encoding="utf-8")
        self.options = ["--input", self.signins, "--input", self.audit]

    def test_inventory_provenance_and_drilldown(self):
        inventory, first, second, report = map(data, exchange(self.options,
            tool("case_overview"), tool("search_events", limit=1),
            tool("search_events", limit=1, offset=1), tool("case_statistics", report="operations")))
        self.assertEqual(len(inventory["logs"]), 2)
        coverage = inventory["case_source_coverage"]
        self.assertEqual(coverage["exchange_trace"]["status"], "not identified")
        self.assertEqual(coverage["sign_ins"]["records"], 1)
        self.assertEqual(inventory["logs"][0]["sha256"], hashlib.sha256(self.signins.read_bytes()).hexdigest())
        self.assertEqual(first["next_offset"], 1)
        self.assertIsNone(second["next_offset"])
        event = second["events"][0]
        self.assertTrue(event["location"].endswith(" /0"))
        group = next(r for r in report["groups"] if r["dimensions"]["operation"] == "Send")
        hit, record = map(data, exchange(self.options, tool("search_events", bql=group["bql"]),
                                         tool("inspect_event", event_key=event["event_key"])))
        self.assertEqual(hit["events"], [event])
        self.assertEqual(record["sha256"], hashlib.sha256(self.audit.read_bytes()).hexdigest())
        self.assertEqual(record["record"]["Item"], {"Subject": "Synthetic invoice"})
        self.assertIs(record["record"]["Flag"], False)

    def test_runbook_and_containment_boundary(self):
        params = dict(mailbox="user@example.org", start_utc="2026-01-01T00:00:00Z",
                      containment_utc="2026-01-02T00:00:00Z", end_utc="2026-01-03T00:00:00Z")
        descriptions, prompt, comparison = exchange(self.options, request("prompts/list"),
            request("prompts/get", {"name": "plan_collection"}), tool("compare_containment", **params))
        self.assertEqual(len(descriptions["prompts"]), 5)
        self.assertIn("50,000", prompt["messages"][0]["content"]["text"])
        review = data(comparison)
        self.assertEqual(review["before"]["observations"]["successful_sign_ins"]["count"], 1)
        self.assertEqual(review["before"]["observations"]["outbound_send_operations"]["count"], 0)
        sent = review["after"]["observations"]["outbound_send_operations"]
        self.assertEqual(sent["count"], 1)
        self.assertEqual(len(data(exchange(self.options, tool("search_events", bql=sent["bql"]))[0])["events"]), 1)
        params["end_utc"] = params["start_utc"]
        self.assertTrue(exchange(self.options, tool("compare_containment", **params))[0]["isError"])

    def test_export_and_reimport(self):
        for fmt in ("csv", "json", "xlsx"):
            with self.subTest(fmt=fmt):
                path = Path(data(exchange([*self.options, "--export-dir", self.root],
                    tool("export_events", format=fmt, bql='operation = "Send"'))[0])["path"])
                self.assertTrue(path.is_relative_to(self.root))
                if fmt == "json":
                    self.assertIs(json.loads(path.read_text(encoding="utf-8"))[0]["Record"]["Flag"], False)
                if fmt == "xlsx":
                    with ZipFile(path) as book:
                        self.assertIn("xl/workbook.xml", book.namelist())
                rows = data(exchange(["--input", path], tool("search_events"))[0])["events"]
                self.assertEqual([r["operation"] for r in rows], ["Send"])

    def test_invalid_calls_and_disabled_exports(self):
        inventory, *failures = exchange(self.options, request("tools/list"),
            tool("export_events", format="json"), tool("search_events", limit=101),
            tool("search_events", bql="madeup = broken"), tool("case_overview", path="another.bec"),
            tool("inspect_event", event_key=999))
        self.assertNotIn("export_events", [t["name"] for t in inventory["tools"]])
        self.assertTrue(all(result["isError"] for result in failures))

    def test_sparse_and_large_records(self):
        self.audit.write_text(json.dumps([{"Operation": "A", "Note": "first"}, {"Flag": None},
                                          {"Operation": "C", "Note": "x" * 9000}]))
        sparse, first, last = map(data, exchange(["--input", self.audit], tool("inspect_event", event_key=2),
            tool("inspect_event", event_key=3), tool("inspect_event", event_key=3, offset=8192)))
        self.assertEqual(sparse["record"], {"Flag": None})
        self.assertEqual(first["next_offset"], 8192)
        self.assertIsNone(last["next_offset"])
        values = json.loads(first["values_json_fragment"] + last["values_json_fragment"])
        self.assertIn("x" * 9000, values)

    def test_existing_case_is_read_only(self):
        case = self.root / "existing.bec"
        with sqlite3.connect(case) as db:
            db.executescript("""
                PRAGMA application_id=1111835441;
                PRAGMA user_version=2;
                CREATE TABLE verdict_rules(id INTEGER);
                CREATE TABLE files(id INTEGER, digest TEXT);
                CREATE TABLE logs(id INTEGER, file INTEGER, name TEXT, sheet TEXT, kind TEXT,
                                  total INTEGER, issues INTEGER, warning TEXT);
                CREATE TABLE events(id INTEGER,log INTEGER,time TEXT);
                INSERT INTO files VALUES(1,'sample');
                INSERT INTO logs VALUES(1,1,'empty.csv','','Tabular log',0,0,'synthetic warning');
            """)
        db.close()
        before = case.read_bytes()
        log = data(exchange(["--case", case], tool("case_overview"))[0])["logs"][0]
        self.assertEqual(log["warning"], "synthetic warning")
        self.assertIsNone(log["first_observed_utc"])
        self.assertEqual(case.read_bytes(), before)
        invalid = subprocess.run([BINARY, "--case", str(self.signins)], capture_output=True, timeout=5)
        self.assertNotEqual(invalid.returncode, 0)

    def test_trace_and_graph_evidence(self):
        trace = self.root / "trace.csv"
        trace.write_text("origin_timestamp,sender_address,recipient_status,message_id\n"
                         "2026-01-02T12:00:00Z,user@example.org,vendor@example.org##Deliver,<sample>\n")
        audit = self.root / "directory.json"
        audit.write_text(json.dumps({"value": [{"activityDateTime": "2026-01-02T12:30:00Z",
                                                "activityDisplayName": "Consent to application"}]}))
        empty = self.root / "empty.csv"
        empty.write_text("ActorType,Activity\n")
        overview, results = map(data, exchange(["--input", trace, "--input", audit, "--input", empty],
            tool("case_overview"), tool("search_events", bql='operation contains "consent"')))
        self.assertEqual(overview["case_source_coverage"]["exchange_trace"]["records"], 1)
        self.assertEqual(overview["case_source_coverage"]["directory_audit"]["logs"], 2)
        self.assertTrue(results["events"][0]["location"].endswith("/value/0"))

if __name__ == "__main__":
    unittest.main()
