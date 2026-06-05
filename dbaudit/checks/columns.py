# scans table columns for potentially sensitive unencrypted data

from sqlalchemy.engine import Engine
from sqlalchemy import text
from dbaudit.models import Finding, Severity

# column name patterns tht suggest sensitive data
# check if any of these trings appear anywhere in the column name
SENSITIVE_PATTERNS = [
    "password", "passwd", "secret", "token", "api_key", "apikey", "auth", "credential", "private_key",
    "ssn", "social_security", "credit_card", "card_number", "cvv", "bank_account", "email", "phone",
    "mobile", "address", "dob", "date_of_birth", "salary", "income", "tax_id", "passport", "license",
]

# these column types suggest data is stored as plain readable text
# if a sensitive column uses one of these, its likely unencrypted
PLAIN_TEXT_TYPES = [
    "character varying", "varchar", "text", "char", "character", "tinytext", "mediumtext", "longtext",
]

def _get_columns(engine: Engine, db_type: str) -> list[dict]:
    """
    fetch all column names n types from user-created tables
    returns a list of dicts: {table, column, data_type}
    """
    if db_type == "postgres":
        # information_schema.columns is a standard SQL view - works on both PG n mysql
        # include system schemas (pg_catalog, information_schema) since those arent our data
        query = text("""
                     SELECT table_name, column_name, data_type
                     FROM information_schema.columns
                     WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
                     ORDER BY table_name, column_name
                     """)
    else:
        # in mysql, filter by the actual db name instead of schema exclusions
        query = text("""
                     SELECT table_name, column_name, data_type
                     FROM information_schema.columns
                     WHERE table_schema = DATABASE()
                     ORDER BY table_name, column_name
                     """)

    with engine.connect() as conn:
        rows = conn.execute(query).fetchall()
    
    # convert each row to a plain dict for easier handling
    return [{ "table": r[0], "column": r[1], "data_type": r[2] } for r in rows]

def _is_sensitive(column_name: str) -> bool:
    # check if a column name matches any sensitive pattern
    name_lower = column_name.lower()
    return any(pattern in name_lower for pattern in SENSITIVE_PATTERNS)

def _is_plaintext_type(data_type: str) -> bool:
    # check if a column's data type suggest unencrypted text storage
    return data_type.lower() in PLAIN_TEXT_TYPES

def check_sensitive_columns(engine: Engine, db_type: str) -> Finding:
    """
    find columns tht appear to store sensitive data as plain text
    flags by column name pattern + storage type combination 
    """
    columns = _get_columns(engine, db_type)

    # group findings by table so the output is readable
    # { "users": ["password", "email"], "orders": ["credit_card"] }
    flagged: dict[str, list[str]] = {}

    for col in columns:
        if _is_sensitive(col["column"]) and _is_plaintext_type(col["data_type"]):
            table = col["table"]
            if table not in flagged:
                flagged[table] = []
            flagged[table].append(col["column"])

    if flagged:
        # build a readable summary: "users (password, email), orders (credit_card)"
        summary = "; ".join(
            f"'{table}' ({ ', '.join(cols) })"
            for table, cols in flagged.items()
        )
        return Finding (
            severity = Severity.HIGH,
            title = "Potentially sensitive unencrypted columns",
            description = f"These columns may store sensitive data in plaintext: {summary}. "
                          f"Consider encrypting at the application layer or using pgcrypto.",
            passed = False,
        )
    
    return Finding (
        severity = Severity.INFO,
        title = "Sensitive column scan",
        description = "No obviously sensitive plaintext columns detected.",
        passed = True,
    )

def check_sensitive_column_count(engine: Engine, db_type: str) -> Finding:
    """
    a separate informational check - just reporst HOW MANY potentially
    sensitive column exist, regardless of type. useful for a risk overview
    """
    columns = _get_columns(engine, db_type)
    sensitive = [c for c in columns if _is_sensitive(c["column"])]

    count = len(sensitive)
    tables = len(set(c["table"] for c in sensitive))

    if count == 0:
        return Finding (
            severity = Severity.INFO,
            title = "Sensitive column inventory",
            description = "No columns with sensitive-sounding names found.",
            passed = True,
        )
    
    # this is always INFO - its not a failure, just an inventory finding
    return Finding (
        severity = Severity.INFO,
        title = "Sensitive column inventory",
        description = f"{count} column(s) with sensitive-sounding names across {tables} table(s). "
                      f"Review the HIGH findings above for unencrypted ones.",
                      passed = True,
    )