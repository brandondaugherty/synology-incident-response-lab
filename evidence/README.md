# Evidence Handling

## Source

The investigation used a private HTML export from Synology DSM System logs.

- Evidence window: **2025-07-24 02:55:11 through 2026-10-16 11:48:39**
- Parsed rows: **9,179**
- File size: **2,248,282 bytes**
- SHA-256: `4ddd6329cc7439ee42179f8ea74ab38b2fc0e7fec7a5be5a49e065688a72b3f9`

The hash documents the analyzed evidence without publishing the evidence itself.

## Chain of Custody

1. The original export was preserved outside the repository.
2. Analysis was performed read-only with a local Python parser.
3. The parser extracted aggregate statistics from matching Auto Block records.
4. Public output was reviewed for raw addresses, usernames, hostnames, paths, and unrelated system data.
5. Only the sanitized aggregate dataset was committed.

## Excluded Data

The original export contains information that is unnecessary for public review, including:

- public source IP addresses
- attempted account labels
- host and service details
- file and directory paths
- storage and package events unrelated to this investigation

Raw exports are explicitly excluded by `.gitignore`.

## Evidence Limitations

The source records that Synology blocked a host through SSH or DSM. It does not include the complete authentication sequence that triggered each block, and it does not establish whether any earlier or later login succeeded. A conclusive compromise assessment requires correlation with authentication, account-audit, firewall, router, and endpoint telemetry.
