# Commands Reference

## Process Analysis

```bash
top
ps -ef
ps -fp PID
lsof -p PID
```

## Malware Analysis

```bash
file binary
strings binary
```

## Persistence

```bash
crontab -l
find /home -name ".*.php"
```

## Integrity

```bash
rpm -qf
rpm -V
```

## SSH Hardening

```bash
adduser sysadmin
usermod -aG wheel sysadmin
visudo
sshd -t
systemctl restart sshd
```
