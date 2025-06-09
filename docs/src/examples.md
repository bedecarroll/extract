# Examples

The following snippets demonstrate common usage patterns.

```bash
# Basic extraction from a string
echo "Server at 192.168.1.1 connected" | extract
```

```bash
# Process a log file and remove duplicates
extract < /var/log/firewall.log | sort | uniq
```

```bash
# Interactive mode with your editor
extract
# type or paste text, then save and exit
```

```bash
# Combine with grep to filter for a specific network
extract < syslog.txt | grep "192.168.1."
```
