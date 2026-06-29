# SSH Hardening

## Improvements

- Created dedicated Linux administrator account.
- Granted sudo privileges via wheel group.
- Disabled direct root SSH:

```text
PermitRootLogin no
```

Validated using:

```bash
sshd -t
sshd -T | grep permitrootlogin
```

Result:

```
permitrootlogin no
```
