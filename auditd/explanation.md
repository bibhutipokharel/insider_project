# Auditd Configuration – Insider Threat Monitoring

This project uses Linux Auditd to monitor insider activities at the operating system level.

## Monitored Events

1. **Command Execution**
   - Tracks all executed commands
   - Helps identify suspicious or unauthorized actions

2. **Home Directory Access**
   - Monitors access to /home directories
   - Detects employees accessing sensitive files

3. **System Configuration Changes**
   - Watches /etc and sudoers
   - Detects privilege escalation attempts

4. **USB Device Activity**
   - Monitors /dev access
   - Detects USB insertion and file access from removable media

## Why Auditd?

Auditd provides reliable, tamper-resistant logging directly from the Linux kernel,
making it suitable for real-world insider threat detection.
