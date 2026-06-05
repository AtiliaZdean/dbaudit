# 🔍 dbaudit

A command-line database auditing and vulnerability scanner for **PostgreSQL** and **MySQL**.

Connects to a live database and checks for common security misconfigurations — weak permissions,
unencrypted sensitive columns, missing SSL, and more.

---

## Demo

![dbaudit terminal output](docs/demo.png)

---

## Checks Performed

| Category | Check | Severity |
|---|---|---|
| Users | Unexpected superuser accounts | HIGH |
| Users | Accounts with no password | CRITICAL |
| Users | High user account count | LOW |
| Permissions | Public schema CREATE access | MEDIUM |
| Permissions | Users with excessive privileges | MEDIUM |
| Config | SSL not enabled | HIGH |
| Config | Users with unlimited connections | LOW |
| Config | Query logging disabled | MEDIUM |
| Schema | Sensitive unencrypted columns | HIGH |
| Schema | Sensitive column inventory | INFO |

---

## Installation

```bash
git clone https://github.com/AtiliaZdean/dbaudit.git
cd dbaudit
python -m venv venv
venv\Scripts\activate
pip install -e .
```

## Usage

```bash
# Basic scan (prompts for password)
dbaudit scan --host localhost --db mydb --user postgres --db-type postgres

# Save HTML report
dbaudit scan --host localhost --db mydb --user postgres --db-type postgres --output report.html

# Save JSON report
dbaudit scan --host localhost --db mydb --user postgres --db-type postgres --output report.json

# MySQL
dbaudit scan --host localhost --db mydb --user root --db-type mysql
```

## Options

| Flag | Description | Default |
|---|---|---|
| `--host` | Database host | required |
| `--port` | Database port | 5432 / 3306 |
| `--db` | Database name | required |
| `--user` | Username | required |
| `--password` | Password (prompted securely) | required |
| `--db-type` | `postgres` or `mysql` | `postgres` |
| `--output` | Save report to `.json` or `.html` | none |

---

## Project Structure
dbaudit/
├── dbaudit/
│   ├── cli.py              # Entry point and CLI definition
│   ├── connector.py        # Database connection layer
│   ├── models.py           # Shared data structures (Finding, Severity)
│   ├── reporter.py         # Terminal, JSON, and HTML output
│   └── checks/
│       ├── users.py        # User and account checks
│       ├── permissions.py  # Privilege checks
│       ├── config.py       # Configuration checks
│       └── columns.py      # Sensitive column scanner
├── .github/workflows/
│   └── ci.yml              # GitHub Actions CI
├── pyproject.toml
├── .env.example
└── README.md

---

## Tech Stack

| Tool | Purpose |
|---|---|
| Python 3.10+ | Core language |
| Typer | CLI framework |
| Rich | Terminal formatting |
| SQLAlchemy | Database abstraction |
| psycopg2 | PostgreSQL driver |
| PyMySQL | MySQL driver |

---

## Author

**Atilia Zainuddin** 
— GitHub: [@AtiliaZdean](https://github.com/AtiliaZdean)