# M365-BEC-MCP

This is the MCP server for **[M365 Email Log Analyzer](https://github.com/xss3cut10n3r/M365-BEC)**, the desktop app for investigating Microsoft 365 email compromise.

Point Claude, or any MCP client, at your Purview audit, Entra sign-in, Entra directory audit, and Exchange message trace exports and let it search the timeline, mark what is malicious, and export the findings.

It reads and writes the same `.bec` case files as the desktop app. Your original files are never changed.

**[Windows x64](https://github.com/xss3cut10n3r/M365-BEC-MCP/releases/latest/download/M365-BEC-MCP-windows-x64.zip)** | **[Linux x64](https://github.com/xss3cut10n3r/M365-BEC-MCP/releases/latest/download/M365-BEC-MCP-linux-x64.tar.gz)**

## Usage

1. Extract the download.
2. Add the server to your MCP client with absolute paths, then restart the client.
3. Ask a question, such as "Who signed in to this mailbox from outside the UK, and what did they send?"

```sh
claude mcp add m365-bec -- C:/tools/M365-BEC-MCP/bin/m365-bec-mcp.exe --case C:/cases/incident.bec --allow-marks
```

```json
{
  "mcpServers": {
    "m365-bec": {
      "command": "C:/tools/M365-BEC-MCP/bin/m365-bec-mcp.exe",
      "args": ["--case", "C:/cases/incident.bec", "--allow-marks"]
    }
  }
}
```

Replies contain evidence from the case and are visible to the MCP client and its model.

## Options

| Argument | Effect |
| --- | --- |
| `--case CASE.bec` | Open a case. Read-only unless an option below is given. |
| `--input FILE` | Import a CSV, Excel, or JSON export. With `--case` it is saved in that case; alone it uses a temporary one. Repeatable. |
| `--allow-marks` | Let the client mark events good, bad, or unsure. |
| `--export-dir DIRECTORY` | Let the client export into this folder. |
| `--full-output` | Send unclipped values and MCP `structuredContent`. |

## Tools

| Tool | Purpose |
| --- | --- |
| `case_overview` | Logs, hashes, date coverage, warnings, and missing sources. |
| `search_events` | Filter the timeline, with extra columns on request. |
| `inspect_event` | One original record, or one field of it. |
| `case_statistics` | Counts by IP, account, device, location, operation, and more. |
| `compare_containment` | A mailbox before and after a containment time. |
| `mark_events` | Mark by filter, IP, event, or time range, with undo. |
| `export_events` | Save events as CSV, Excel, or JSON. |

Filters use the app's syntax:

```text
mailbox = "analyst@example.org" AND operation contains "InboxRule"
field "/status/errorCode" = "50126"
```

Five prompts cover collection, intake, investigation, containment, and handoff. See the [investigation guide](docs/investigation.md).

## Build

C17 with SQLite and CMake. See the [build instructions](docs/build.md).

The Linux download targets Ubuntu 24.04 and needs these packages:

```sh
sudo apt install libglib2.0-0t64 libsqlite3-0 libexpat1 libzip4t64 libxlsxwriter5
```

[GPL-3.0](LICENSE)
