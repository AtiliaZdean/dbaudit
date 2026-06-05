# checks related to database users n accounts including superuser accounts, users w/ no pw, default users

from sqlalchemy.engine import Engine
from sqlalchemy import text
from dbaudit.models import Finding, Severity

def check_superusers(engine: Engine, db_type: str) -> Finding:
    """
    find non-system accounts that have full superuser/admin priviledges
    a superuser can do anything - bypass row security, read all data, drop tables
    in production, only dedicated admin accounts should have this
    """
    if db_type == "postgres":
        # pg_roles is psql's built-in table of all users/roles
        # usecreatedb/usesuper are boolean columns - True means they have tht privilege
        query = text("""
            SELECT usename
            FROM pg_user
            WHERE usesuper = TRUE
            AND usename NOT IN ('postgres')             
        """)
    else:
        # in mysql, 'root' is the default superuser - any others are suspicious
        query = text("""
                     SELECT user, host
                     FROM mysql.user
                     WHERE Super_priv = 'Y'
                     AND user NOT IN ('root', 'mysql.sys', 'mysql.session', 'mysql.infoschema')
                     """)

    with engine.connect() as conn:
        results = conn.execute(query).fetchall()

    if results:
        # list the suspicious accounts in the description
        accounts = ", ".join(row[0] for row in results)
        return Finding(
            severity = Severity.HIGH,
            title = "Unexpected superuser accounts found",
            description = f"These accounts have full superuser privileges: {accounts}. "
                          f"Superuser access should be limited to dedicated admin accounts only.",
            passed = False,
        )
    
    return Finding (
        severity = Severity.INFO,
        title = "Superuser accounts",
        description = "No unexpected superuser accounts found.",
        passed = True,
    )

def check_users_without_password(engine: Engine, db_type: str) -> Finding:
    """
    find the accounts with no password set
    these can be logged into without any credentials - a critical risk
    """
    if db_type == "postgres":
        # passwd in pg_shadow is NULL or empty string if no password is set
        query = text("""
                     SELECT usename
                     FROM pg_shadow
                     WHERE passwd IS NULL OR passwd = ''
                     """)
    else:
        query = text("""
                     SELECT user, host
                     FROM mysql.user
                     WHERE authentication_string = ''
                     AND account_locked = 'N'
                     """)

    with engine.connect() as conn:
        results = conn.execute(query).fetchall()

    if results:
        accounts = ", ".join(row[0] for row in results)
        return Finding(
            severity = Severity.CRITICAL,
            title = "Accounts with no password",
            description = f"These accounts have no password set: {accounts}. "
                          f"Anyone can log in as these users wiothout credentials.",
            passed = False,
        )
    
    return Finding (
        severity = Severity.INFO,
        title = "Password check",
        description = "All accounts have passwords set.",
        passed = True,
    )

def check_user_count(engine: Engine, db_type: str) -> Finding:
    """
    count total DB users. a high number of accounts increases the attack surface.
    this is informational - flags it for the dba to review.
    """
    if db_type == "postgres":
        query = text("SELECT COUNT(*) FROM pg_user")
    else:
        query = text("SELECT COUNT(*) FROM mysql.user")

    with engine.connect() as conn:
        count = conn.execute(query).scalar()    # .scalar() returns a single value

    # more than 10 users is worth flagging for review
    if count > 10:
        return Finding(
            severity = Severity.LOW,
            title = "High number of database users",
            description = f"{count} user accounts exist. Review whether all are still needed.",
            passed = False,
        )
    
    return Finding (
        severity = Severity.INFO,
        title = "User account count",
        description = f"{count} user accounts found - within normal range.",
        passed = True,
    )