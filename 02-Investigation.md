# Investigation

## Findings

### Hidden Linux Malware

- Hidden ELF executable discovered outside the web root.
- Executed under the hosting account.
- Disguised related processes as kernel worker threads.

### Persistence

- Base64-encoded cron job executed hourly.
- Hidden PHP webshells discovered in CMS directories.
- Multiple deployment waves suggested long-term persistence.

### Validation

System integrity verified with:

```bash
rpm -qf /usr/bin/vi
rpm -V vim-minimal
```

Package verification passed with no unexpected modifications.
