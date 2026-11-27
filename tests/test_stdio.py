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
    payload = json.loads(result["content"][0]["text"])
    if "structuredContent" in result:
        assert result["structuredContent"] == payload
    return payload


def table(payload, name="rows"):
    return [dict(zip(payload["columns"], row)) for row in payload[name]]


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
            tool("search_events", limit=1, offset=1), tool("case_statistics", reports=["operations", "mailboxes"])))
        logs = table(inventory, "logs")
        self.assertEqual(len(logs), 2)
        self.assertIn("exchange_trace", inventory["coverage"]["missing"])
        self.assertEqual(inventory["coverage"]["sign_ins"], 1)
        self.assertNotIn("mark_rules", inventory)
        self.assertEqual(logs[0]["sha256"], hashlib.sha256(self.signins.read_bytes()).hexdigest())
        self.assertEqual(logs[0]["first_utc"], "2026-01-01T12:00:00Z")
        self.assertEqual((first["total"], first["next_offset"]), (2, 1))
        self.assertNotIn("next_offset", second)
        event = table(second)[0]
        self.assertEqual((event["log"], event["row"], event["utc"]), (2, 1, "2026-01-02T00:00:00Z"))
        self.assertEqual(set(report), {"operations", "mailboxes"})
        group = next(r for r in table(report["operations"]) if r["operation"] == "Send")
        self.assertEqual(group["count"], 1)
        hit, record = map(data, exchange(self.options, tool("search_events", bql='operation = "Send"'),
                                         tool("inspect_event", event_key=event["key"])))
        self.assertEqual(table(hit), [event])
        self.assertTrue(record["location"].endswith(" /0"))
        self.assertEqual(record["record"]["Item"], {"Subject": "Synthetic invoice"})
        self.assertIs(record["record"]["Flag"], False)
        full = data(exchange([*self.options, "--full-output"], tool("inspect_event", event_key=event["key"]))[0])
        self.assertEqual(full["sha256"], hashlib.sha256(self.audit.read_bytes()).hexdigest())

    def test_runbook_and_containment_boundary(self):
        params = dict(mailbox="user@example.org", start_utc="2026-01-01T00:00:00Z",
                      containment_utc="2026-01-02T00:00:00Z", end_utc="2026-01-03T00:00:00Z")
        descriptions, prompt, comparison = exchange(self.options, request("prompts/list"),
            request("prompts/get", {"name": "plan_collection"}), tool("compare_containment", **params))
        self.assertEqual(len(descriptions["prompts"]), 5)
        self.assertIn("50,000", prompt["messages"][0]["content"]["text"])
        review = data(comparison)
        self.assertEqual(review["counts_before_after"]["successful_sign_ins"], [1, 0])
        self.assertEqual(review["counts_before_after"]["outbound_send_operations"], [0, 1])
        category = review["category_bql"]["outbound_send_operations"]
        sent = f'({review["after_bql"]}) AND ({category})'
        self.assertEqual(len(data(exchange(self.options, tool("search_events", bql=sent))[0])["rows"]), 1)
        full, = exchange([*self.options, "--full-output"], tool("compare_containment", **params))
        self.assertEqual(full["structuredContent"], data(full))
        for name, pair in review["counts_before_after"].items():
            legacy = [data(full)[period]["observations"][name]["count"] for period in ("before", "after")]
            self.assertEqual(pair, legacy)
        params["end_utc"] = params["start_utc"]
        self.assertTrue(exchange(self.options, tool("compare_containment", **params))[0]["isError"])

    def test_export_and_reimport(self):
        for fmt in ("csv", "json", "xlsx"):
            with self.subTest(fmt=fmt):
                saved = data(exchange([*self.options, "--export-dir", self.root],
                    tool("export_events", format=fmt, bql='operation = "Send"', fields=["/Item/Subject"]))[0])
                path = Path(saved["path"])
                self.assertEqual(saved["events"], 1)
                self.assertTrue(path.is_relative_to(self.root))
                if fmt == "json":
                    row = json.loads(path.read_text(encoding="utf-8"))[0]
                    self.assertIs(row["Record"]["Flag"], False)
                    self.assertEqual(row["Field /Item/Subject"], "Synthetic invoice")
                if fmt == "xlsx":
                    with ZipFile(path) as book:
                        self.assertIn("xl/workbook.xml", book.namelist())
                rows = table(data(exchange(["--input", path], tool("search_events"))[0]))
                self.assertEqual([r["operation"] for r in rows], ["Send"])

    def test_invalid_calls_and_disabled_tools(self):
        case = self.root / "locked.bec"
        exchange(["--case", case, *self.options], tool("case_overview"))
        inventory, *failures = exchange(["--case", case], request("tools/list"),
            tool("export_events", format="json"), tool("search_events", limit=201),
            tool("search_events", bql="madeup = broken"), tool("case_overview", path="another.bec"),
            tool("inspect_event", event_key=999), tool("mark_events", verdict="Bad", ips=["192.0.2.8"]),
            tool("case_statistics", reports=["nonsense"]), tool("search_events", fields=["nonsense"]),
            tool("inspect_event", event_key=1, field="Username"))
        names = [t["name"] for t in inventory["tools"]]
        self.assertNotIn("export_events", names)
        self.assertNotIn("mark_events", names)
        self.assertTrue(all(result["isError"] for result in failures))
        messages = [result["content"][0]["text"] for result in failures]
        self.assertIn("Fields: ", messages[2])
        self.assertIn("mailbox", messages[2])
        self.assertIn("limit", messages[3])
        self.assertIn("indicators", messages[6])
        self.assertIn("location", messages[7])
        search = next(t for t in inventory["tools"] if t["name"] == "search_events")
        self.assertIn("raw contains", search["description"])
        self.assertIn("mailbox", search["description"])
        self.assertLess(len(json.dumps(inventory)), 5200)

    def test_nested_and_large_records(self):
        self.audit.write_text(json.dumps([{"Operation": "A", "Note": "first", "Empty": "", "None": None},
                                          {"Flag": None},
                                          {"Operation": "C", "Note": "x" * 9000},
                                          {"Operation": "D", **{f"k{i}": "y" * 390 for i in range(40)}}]))
        options = ["--input", self.audit]
        plain, sparse, clipped, huge = map(data, exchange(options, *[tool("inspect_event", event_key=k) for k in (1, 2, 3, 4)]))
        self.assertEqual(plain["record"], {"Operation": "A", "Note": "first"})
        self.assertEqual(sparse["record"], {})
        self.assertIn("clipped", clipped)
        self.assertTrue(clipped["record"]["Note"].endswith("[+8600 chars]"))
        self.assertNotIn("record", huge)
        self.assertIn("/k39", huge["paths"])
        first = data(exchange(options, tool("inspect_event", event_key=3, field="/Note"))[0])
        parts, page = [first["value"]], first
        while "next_offset" in page:
            page = data(exchange(options, tool("inspect_event", event_key=3, field="/Note", offset=page["next_offset"]))[0])
            parts.append(page["value"])
        self.assertEqual("".join(parts), "x" * 9000)
        raw = data(exchange([*options, "--full-output"], tool("inspect_event", event_key=2))[0])
        self.assertEqual(raw["record"], {"Flag": None})

    def test_embedded_json_and_subtrees(self):
        audit = self.root / "purview.csv"
        detail = {"Operation": "New-InboxRule", "ClientIP": "198.51.100.7", "Empty": "", "Item": {"Subject": "Invoice 7", "Attachments": ""},
                  "Parameters": [{"Name": "DeleteMessage", "Value": "True"}, {"Name": "Name", "Value": "/"}]}
        with audit.open("w", newline="", encoding="utf-8") as out:
            writer = csv.writer(out)
            writer.writerow(["CreationDate", "UserIds", "Operations", "AuditData"])
            writer.writerow(["2026-01-03T10:00:00Z", "user@example.org", "New-InboxRule", json.dumps(detail)])
        options = ["--input", audit]
        whole, branch, leaf, wild, miss, rows = map(data, exchange(options,
            tool("inspect_event", event_key=1), tool("inspect_event", event_key=1, field="/AuditData/Parameters"),
            tool("inspect_event", event_key=1, field="/AuditData/Item/Subject"),
            tool("inspect_event", event_key=1, field="/AuditData/Parameters/*/Name"),
            tool("inspect_event", event_key=1, field="/AuditData/Missing"),
            tool("search_events", fields=["subject", "/AuditData/Parameters/1/Value", "rule"])))
        self.assertEqual(whole["record"]["AuditData"]["Item"], {"Subject": "Invoice 7"})
        self.assertNotIn("Empty", whole["record"]["AuditData"])
        self.assertEqual(whole["location"], "purview.csv · row 2")
        self.assertEqual(branch["value"], detail["Parameters"])
        self.assertEqual(leaf["value"], "Invoice 7")
        self.assertEqual(wild["value"], ["DeleteMessage", "Name"])
        self.assertFalse(miss["present"])
        self.assertNotIn("value", miss)
        row = table(rows)[0]
        self.assertEqual((row["subject"], row["/AuditData/Parameters/1/Value"], row["rule"]), ("Invoice 7", "/", "/"))

    def test_compact_paging_and_clipping(self):
        self.audit.write_text(json.dumps([{"Operation": "x" * 800, "UserId": "user@example.org"}] * 150))
        options = ["--input", self.audit]
        default, broad = exchange(options, tool("search_events"), tool("search_events", limit=200))
        self.assertNotIn("structuredContent", default)
        self.assertEqual(len(data(default)["rows"]), 20)
        self.assertEqual(data(default)["total"], 150)
        seen, page, calls = [], data(broad), 1
        while True:
            self.assertLess(len(json.dumps(page, separators=(",", ":")).encode()), 13000)
            self.assertIn("clipped", page)
            seen += [row[0] for row in page["rows"]]
            if "next_offset" not in page:
                break
            page = data(exchange(options, tool("search_events", limit=200, offset=page["next_offset"]))[0])
            calls += 1
        self.assertEqual(seen, list(range(1, 151)))
        self.assertLessEqual(calls, 4)
        latest = data(exchange(options, tool("search_events", limit=2, order="desc"))[0])
        self.assertEqual([row[0] for row in latest["rows"]], [150, 149])
        legacy, = exchange([*options, "--full-output"], tool("search_events"))
        self.assertEqual(table(legacy["structuredContent"])[0]["operation"], "x" * 800)

    def test_marks_are_opt_in_and_saved(self):
        case = self.root / "marked.bec"
        writable = ["--case", case, "--allow-marks", "--export-dir", self.root]
        created = data(exchange(["--case", case, *self.options], tool("case_overview"))[0])
        self.assertEqual(len(created["logs"]), 2)
        by_ip, by_bql, by_key, by_time, overview, found, saved = map(data, exchange(writable,
            tool("mark_events", verdict="Bad", ips=["192.0.2.8"]),
            tool("mark_events", verdict="Good", bql='operation = "Send"'),
            tool("mark_events", verdict="Unsure", event_keys=[2]),
            tool("mark_events", verdict="Bad", start_utc="2026-01-02T00:00:00Z", end_utc="2026-01-02T00:00:01Z"),
            tool("case_overview"), tool("search_events", bql="marked = true"),
            tool("export_events", format="xlsx", bql="marked = true")))
        self.assertEqual([r["events"] for r in (by_ip, by_bql, by_key, by_time)], [1, 1, 1, 1])
        self.assertEqual(overview["mark_rules"], 4)
        self.assertEqual([row["verdict"] for row in table(found)], ["Bad", "Bad"])
        with ZipFile(saved["path"]) as book:
            self.assertIn("FFC7CE", book.read("xl/styles.xml").decode())
        undone, after, *failures = exchange(writable, tool("mark_events", undo=True), tool("search_events", bql="verdict = Unsure"),
            tool("mark_events", verdict="Bad"), tool("mark_events", verdict="Bad", event_keys=[1, 99]),
            tool("mark_events", verdict="Bad", ips=["not an ip"]), tool("mark_events", verdict="Maybe", ips=["192.0.2.8"]),
            tool("mark_events", verdict="Bad", ips=["192.0.2.8"], bql="marked = true"),
            tool("mark_events", verdict="Bad", start_utc="2026-01-02T00:00:00Z"))
        self.assertTrue(data(undone)["undone"])
        self.assertEqual(table(data(after))[0]["key"], 2)
        self.assertTrue(all(result["isError"] for result in failures))
        reopened = data(exchange(["--case", case], tool("search_events", bql="marked = true"))[0])
        self.assertEqual([row["verdict"] for row in table(reopened)], ["Bad", "Unsure"])
        again = data(exchange(["--case", case, *self.options], tool("case_overview"))[0])
        self.assertEqual(len(again["logs"]), 2)
        missing = subprocess.run([BINARY, "--case", str(self.root / "absent.bec")], capture_output=True, timeout=5)
        self.assertNotEqual(missing.returncode, 0)

    def test_existing_case_is_read_only(self):
        case = self.root / "existing.bec"
        with sqlite3.connect(case) as db:
            db.executescript("""
                PRAGMA application_id=1111835441;
                PRAGMA user_version=2;
                CREATE TABLE verdict_rules(id INTEGER);
                CREATE TABLE marks(id INTEGER);
                CREATE TABLE files(id INTEGER, digest TEXT);
                CREATE TABLE logs(id INTEGER, file INTEGER, name TEXT, sheet TEXT, kind TEXT,
                                  total INTEGER, issues INTEGER, warning TEXT);
                CREATE TABLE events(id INTEGER,log INTEGER,time TEXT);
                INSERT INTO files VALUES(1,'sample');
                INSERT INTO logs VALUES(1,1,'empty.csv','','Tabular log',0,0,'synthetic warning');
            """)
        db.close()
        before = case.read_bytes()
        log = table(data(exchange(["--case", case], tool("case_overview"))[0]), "logs")[0]
        self.assertEqual(log["warning"], "synthetic warning")
        self.assertEqual(log["first_utc"], "")
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
        options = ["--input", trace, "--input", audit, "--input", empty]
        overview, results, stats = map(data, exchange(options,
            tool("case_overview"), tool("search_events", bql='operation contains "consent"'),
            tool("case_statistics", reports=["indicators", "conversations", "activity"])))
        self.assertEqual(overview["coverage"]["exchange_trace"], 1)
        self.assertEqual(overview["coverage"]["directory_audit"], 1)
        key = table(results)[0]["key"]
        located = data(exchange(options, tool("inspect_event", event_key=key))[0])
        self.assertTrue(located["location"].endswith("/value/0"))
        consent = next(r for r in table(stats["indicators"]) if "consent" in r["indicator"])
        self.assertIn("consent", consent["bql"])
        self.assertTrue(all(r["count"] for r in table(stats["indicators"])))
        self.assertIn("scope", stats["conversations"])
        self.assertEqual(table(stats["activity"])[0]["time"], "2026-01-02T12:00:00Z")


if __name__ == "__main__":
    unittest.main()
