# M365-BEC-MCP

Investigate Microsoft 365 business email compromise from an MCP client. The local C17 server uses the desktop analyzer’s engine to search Entra, Purview and Exchange evidence. Each timeline result links back to a file and source location.

## Connect a case

Download **[Windows x64](https://github.com/xss3cut10n3r/M365-BEC-MCP/releases/latest/download/M365-BEC-MCP-windows-x64.zip)** or **[Linux x64](https://github.com/xss3cut10n3r/M365-BEC-MCP/releases/latest/download/M365-BEC-MCP-linux-x64.tar.gz)** and extract it, or build the server using the [build instructions](docs/build.md). The Linux build targets Ubuntu 24.04 and needs `libglib2.0-0t64 libsqlite3-0 libexpat1 libzip4t64 libxlsxwriter5`. Add this entry to your MCP client's configuration, replacing both paths with absolute paths on your machine.

```json
{
  "mcpServers": {
    "m365-bec": {
      "command": "C:/tools/m365-bec-mcp/bin/m365-bec-mcp.exe",
      "args": ["--case", "C:/cases/incident.bec"]
    }
  }
}
```

On Linux, use the installed `bin/m365-bec-mcp` path. Restart the client after changing its configuration. In Claude Code, run `claude mcp add m365-bec -- C:/tools/m365-bec-mcp/bin/m365-bec-mcp.exe --case C:/cases/incident.bec --allow-marks`.

| Argument | Effect |
| --- | --- |
| `--case CASE.bec` | Open an analyzer case. It stays read-only unless another argument below says otherwise. |
| `--input FILE` | Import a CSV, XLSX or JSON export. With `--case` the logs are saved in that case, which is created when missing. Alone, they share a temporary case for the session. Repeatable. |
| `--allow-marks` | Enable `mark_events` so verdicts are saved in the case and show in the desktop analyzer. |
| `--export-dir DIRECTORY` | Enable `export_events` into an existing directory. |
| `--full-output` | Send unclipped values, raw records and MCP `structuredContent`. |

Use one tenant per case. Imports never change the original files, and marks never change the evidence stored in a case. The server communicates over stdio. Its replies can contain sensitive evidence and are visible to the configured MCP client and its model.

## Investigate

Start with “What evidence do we have, which sources are missing, and which exports show warnings?” Then ask “What changed for this mailbox after containment? Show the UTC times and source records.”

| Tool | Purpose |
| --- | --- |
| `case_overview` | Inventory files, hashes, observed dates, undated rows, import issues and source coverage. |
| `search_events` | Filter the UTC timeline with BQL. `fields` adds columns such as `subject`, `location` or `/AuditData/Item/Attachments`. |
| `inspect_event` | Read one source record as nested JSON, or one subtree or value with `field`. |
| `case_statistics` | Count groups for several reports at once: sign-in outcomes, devices, mail flow, rules, grants and mailbox access. |
| `compare_containment` | Compare a mailbox before and after a responder-supplied UTC timestamp. |
| `mark_events` | Mark events Good, Bad or Unsure by filter, IP address, event key or time range. `undo` reverts the last mark. |
| `export_events` | Save filtered rows as CSV, XLSX or JSON. XLSX rows are coloured by verdict. |

For a timeline search, try `mailbox = "user@example.org" AND operation contains "InboxRule"`. The `search_events` description lists every filter field, and `raw contains "text"` searches whole records. To inspect a statistics group, search for its dimension, such as `ip = "203.0.113.7"`, joined with the report's `scope` when one is given. Follow `next_offset` for additional results. The event key stays tied to its source record within the case.

Five prompts guide collection planning, intake, investigation, containment verification and handoff. [Investigation guide](docs/investigation.md)

## Response size

Results are tables: one `columns` list and one array per row. A row's `log` and `row` give its source file, through `case_overview`, and its line. Whole-second times drop the fraction. Searches return 20 rows by default, statistics 15 groups per report, and up to 200 with `limit`. A page holds about 12 KiB, so follow `next_offset` when it appears. Cells longer than 192 characters are cut and the result says so.

`inspect_event` decodes embedded JSON such as `AuditData`, omits empty values and cuts strings at 400 characters. Pass `field` for an exact value, which pages by `offset` when long. A record too large for one reply lists its field paths instead.

Containment counts are ordered `[before, after]`. To investigate a count, join the period’s BQL and the category’s BQL with `AND`, enclosing each in parentheses. The period filter alone reproduces the total.
