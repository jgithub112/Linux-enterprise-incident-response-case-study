# Detection Opportunities

> **Tooling context:** At the time of the incident, monitoring on the affected server consisted of **LFD/CSF and Imunify360** — no SIEM or EDR agent was deployed. The detections proposed below are improvements identified during the post-incident review. They are implemented and tested in a **separate lab environment**, not on the affected production system.

## What the Existing Stack Caught — and Couldn't

| Capability | LFD/CSF + Imunify360 | Gap |
|------------|----------------------|-----|
| Resource abuse (high CPU/process time) | ✅ Caught — this is what triggered the investigation | Detection was **late-stage**: the implant was already running |
| SSH brute-force blocking | ✅ Automatic IP blocking worked throughout | — |
| Known-malware PHP signatures | ⚠️ Partial — Imunify360 flagged one file | Obfuscated/novel webshells with legitimate-looking names were not flagged |
| Cron/crontab modification | ❌ Not monitored | Persistence was established silently |
| Process lineage anomalies (fake kworker) | ❌ Not monitored | Masquerade was only spotted by manual `ps` analysis |
| File integrity on web root | ❌ Not monitored | Multiple webshell deployment waves went undetected |

**Takeaway:** the existing stack detected the *symptoms* (resource abuse) but not the *behaviors* (persistence, masquerading, file drops). Every proposed detection below targets one of those behavioral gaps.

## Proposed Detections

For each stage of the attack, a detection that would have caught it earlier than resource alerts did. These are written to be implementable in Wazuh / Elastic / any SIEM ingesting Linux logs and FIM data.

| Stage | Detection | Data Source | Logic |
|-------|-----------|-------------|-------|
| Webshell drop | New or modified PHP file in upload/writable dirs | File Integrity Monitoring on web root | Alert on `*.php` created under `wp-content/uploads/**` or any dot-prefixed `.*.php` anywhere in the docroot |
| Payload staging | Executable file created in a home directory | FIM + `auditd` (`execve`) | Alert on ELF magic bytes / `+x` files created outside standard binary paths, especially dot-prefixed |
| Cron persistence | Crontab modification | `auditd` watch on `/var/spool/cron/` | Any write to user crontabs generates an alert; base64 content in a cron line escalates severity |
| Masquerading | "Kernel thread" with wrong lineage | Process telemetry (osquery/EDR/`ps` snapshots) | Process presents a bracketed kernel-thread name (`[slub_*]`, `[kworker*]`) but has an on-disk `/proc/PID/exe`, UID ≠ 0, or PPID ≠ 2 — real kernel threads have none of these |
| Masquerading (mechanism) | `exec -a` argv[0] spoofing | `auditd` `execve` | `execve` where argv[0] starts with `[` and differs from the executable path |
| Execution | Shell spawned by web server user | `auditd` / process events | `bash`/`sh` with parent `php-fpm`/`apache` — near-zero false positives on a CMS host |
| C2 / remote access | gsocket-style outbound channel | NetFlow / firewall / `ss` snapshots | Long-lived outbound connection from a hosting-account process to a relay network; process backed by a binary under `~/.config`, `~/.cache` |
| Anti-forensics | Deleted running executable | osquery (`processes` where `on_disk = 0`) | Running process whose backing binary is deleted |

