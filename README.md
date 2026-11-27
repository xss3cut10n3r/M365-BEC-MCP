# M365-BEC-MCP

Investigate Microsoft 365 business email compromise from an MCP client. The local C17 server uses the desktop analyzer’s engine to search Entra, Purview and Exchange evidence. Each timeline result links back to a file and source location.

## Connect a case

Build the server using the [build instructions](docs/build.md). Add this entry to your MCP client's configuration, replacing both paths with absolute paths on your machine.

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

On Linux, use the installed `bin/m365-bec-mcp` path. Restart the client after changing its configuration.

To investigate raw exports, replace the case arguments with one or more `--input` paths. CSV, XLSX and JSON imports share a temporary case for that server session. Use one tenant per session. Existing cases open read-only. The server communicates over stdio. Its replies can contain sensitive evidence and are visible to the configured MCP client and its model.

## Investigate

Start with “What evidence do we have, which sources are missing, and which exports show warnings?” Then ask “What changed for this mailbox after containment? Show the UTC times and source records.”

| Tool | Purpose |
| --- | --- |
| `case_overview` | Inventory files, hashes, observed dates, undated rows, import issues and source coverage. |
| `search_events` | Filter the UTC timeline with BQL, optionally within one log. |
| `inspect_event` | Look up an event key to inspect its source values and file hash. |
| `case_statistics` | Review sign-ins, device IDs, mail flow, rules, grants and mailbox access. Each group provides a BQL drilldown. |
| `compare_containment` | Compare a mailbox before and after a responder-supplied UTC timestamp. |
| `export_events` | Save filtered rows as CSV, XLSX or JSON when launched with `--export-dir` and an existing directory. |

For a timeline search, try `mailbox = "user@example.org" AND operation contains "InboxRule"`. Copy a statistics group's BQL and log ID into `search_events` to inspect the supporting events. Follow `next_offset` for additional results. The event key stays tied to its source record within the case. The timeline ID reflects chronological order.

Five prompts guide collection planning, intake, investigation, containment verification and handoff. [Investigation guide](docs/investigation.md)
