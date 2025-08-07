  
## 🧭 Basic Usage


```bash

python3 pacu.py

```

### Inside the Console:

```bash

> help                  # Show command list

> set_keys             # Set AWS credentials

> whoami               # Show current user info

> run <module>         # Run a module

> run <module> --help  # Module usage/help

```

---
## 🔑 Set AWS Credentials

```bash

set_keys

```

Provide:

- Access key

- Secret key

- Session token (optional)
---
## 📦 Common Modules

| Category        | Example Modules                            |

|-----------------|---------------------------------------------|

| Enumeration     | `iam__enum_users`, `ec2__enum`, `s3__enum` |

| Privilege Escalation | `iam__privesc_scan`                     |

| Persistence     | `backdoor_assume_role`                     |

| Data Exfiltration | `download_all_buckets`                   |

| Exploitation    | `iam__add_user`, `iam__attach_user_policy` |

---

## 🔍 Useful Enumeration Modules

```bash

run ec2__enum

run iam__enum_permissions

run s3__enum

run sts__enum_account

```

---
## 🔓 Privilege Escalation

```bash

run iam__privesc_scan

```
- Identifies potential privilege escalation paths for the current IAM user.

---
## 📥 Data Exfiltration

```bash

run s3__download_buckets

run dynamodb__download_all_tables

```

---
## 🛠 Persistence

```bash

run backdoor_assume_role

run create_login_profile

```

---
## 💾 Sessions

Pacu stores all data in sessions (similar to Metasploit):

```bash

sessions               # List sessions

switch_session <name> # Switch session

save_session <name>   # Save current session

```

---
## 🧠 Tips

- Use `whoami` to view your current identity and privileges.

- Use `data` to inspect all collected data (AWS services, resources).

- Use `run <module> --help` to see all arguments/options before execution.

- Run `update` to get latest module updates.