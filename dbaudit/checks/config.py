# checks for insecure database configuration settings (SSL enforcement, connection limits, logging settings)

from sqlalchemy.engine import Engine
from sqlalchemy import text
from dbaudit.models import Finding, Severity


def check_ssl_enabled(engine: Engine, db_type: str) -> Finding:
    """
    check if SSL is enforced for connections.
    without SSL, credentials and data travel over the network unencrypted.
    """
    if db_type == "postgres":
        query = text("SHOW ssl")
        with engine.connect() as conn:
            result = conn.execute(query).scalar()
        ssl_on = result == "on"
    else:
        query = text("SHOW VARIABLES LIKE 'have_ssl'")
        with engine.connect() as conn:
            row = conn.execute(query).fetchone()
        ssl_on = row and row[1] == "YES"

    if not ssl_on:
        return Finding (
            severity = Severity.HIGH,
            title = "SSL is not enabled",
            description = "Database connections are not encrypted. Credentials and data "
                          "are transmitted in plaintext. Enable SSL in postgresql.conf: ssl = on",
            passed = False,
        )

    return Finding (
        severity = Severity.INFO,
        title = "SSL status",
        description = "SSL is enabled — connections are encrypted.",
        passed = True,
    )


def check_connection_limit(engine: Engine, db_type: str) -> Finding:
    """
    check if a connection limit is set on user accounts.
    unlimited conns can be abused to exhaust DB resources (DoS).
    """
    if db_type == "postgres":
        # connlimit = -1 means unlimited

        # query = text("""
        #              SELECT usename, conn_limit
        #              FROM pg_user
        #              WHERE conn_limit = -1
        #              AND usename NOT IN ('postgres')
        #              """) 

        query = text("""
                     SELECT rolname, rolconnlimit
                     FROM pg_roles
                     WHERE rolconnlimit = -1
                     AND rolcanlogin = TRUE
                     AND rolname NOT IN ('postgres')
                     """)
    else:
        query = text("""
                     SELECT user, max_connections
                     FROM mysql.user
                     WHERE max_connections = 0
                     AND user NOT IN ('root', 'mysql.sys')
                     """)

    with engine.connect() as conn:
        results = conn.execute(query).fetchall()

    if results:
        accounts = ", ".join(row[0] for row in results)
        return Finding (
            severity = Severity.LOW,
            title = "Users with unlimited connections",
            description = f"These users have no connection limit: {accounts}. "
                          f"Set limits with: ALTER USER username CONNECTION LIMIT 10;",
            passed = False,
        )

    return Finding (
        severity = Severity.INFO,
        title = "Connection limits",
        description = "All non-admin users have connection limits set.",
        passed = True,
    )


def check_logging_enabled(engine: Engine, db_type: str) -> Finding:
    """
    check if query logging is enabled.
    without logging, there's no audit trail for suspicious activity.
    """
    if db_type == "postgres":
        query = text("SHOW log_statement")
        with engine.connect() as conn:
            result = conn.execute(query).scalar()
        # 'all' logs everything, 'ddl' logs schema changes — both are acceptable
        logging_ok = result in ("all", "ddl", "mod")
    else:
        query = text("SHOW VARIABLES LIKE 'general_log'")
        with engine.connect() as conn:
            row = conn.execute(query).fetchone()
        logging_ok = row and row[1] == "ON"

    if not logging_ok:
        return Finding (
            severity = Severity.MEDIUM,
            title = "Query logging is not enabled",
            description = "No query audit trail is configured. Set in postgresql.conf: "
                          "log_statement = 'ddl' (logs schema changes) or 'all' (logs everything).",
            passed = False,
        )

    return Finding (
        severity = Severity.INFO,
        title = "Query logging",
        description = "Query logging is enabled.",
        passed = True,
    )