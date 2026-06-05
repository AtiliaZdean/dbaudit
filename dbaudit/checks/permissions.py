# checks related to privileges and access control (public schema access. excessive privileges)

from sqlalchemy.engine import Engine
from sqlalchemy import text
from dbaudit.models import Finding, Severity


def check_public_schema_access(engine: Engine, db_type: str) -> Finding:
    """
    in psql, the 'public' schema is accessible to all users by default.
    this means any user can create tables in it - a common misconfiguration.
    psql 15+ changed this default,  but older setups are often still exposed.
    """
    if db_type != "postgres":
        return Finding(
            severity = Severity.INFO,
            title = "Public schema check",
            description = "Not applicable for MySQL.",
            passed = True,
        )

    # has_schema_privilege checks if 'public' role can CREATE in the public schema
    # 'public' in psql = every user automatically belongs to this role
    query = text("""
                 SELECT has_schema_privilege('public', 'public', 'CREATE') AS has_create
                 """)

    with engine.connect() as conn:
        result = conn.execute(query).scalar()

    if result:
        return Finding (
            severity = Severity.MEDIUM,
            title = "Public schema CREATE privilege enabled",
            description = "Any database user can create objects in the public schema. "
                          "Run: REVOKE CREATE ON SCHEMA public FROM PUBLIC;",
            passed = False,
        )

    return Finding (
        severity = Severity.INFO,
        title = "Public schema access",
        description = "Public schema CREATE privilege is restricted.",
        passed = True,
    )


def check_excessive_privileges(engine: Engine, db_type: str) -> Finding:
    # find regular (non-super) users who have been granted all privileges on the database — nearly as dangerous as superuser.
    
    if db_type == "postgres":
        # pg_database_privileges checks what privileges exist on the DB itself
        query = text("""
                     SELECT grantee
                     FROM information_schema.role_table_grants
                     WHERE privilege_type = 'DELETE'
                     AND grantee NOT IN ('postgres', 'PUBLIC')
                     GROUP BY grantee
                     HAVING COUNT(*) > 10
                     """)
    else:
        query = text("""
                     SELECT user, host
                     FROM mysql.user
                     WHERE Select_priv='Y' AND Insert_priv='Y'
                     AND Update_priv='Y' AND Delete_priv='Y'
                     AND user NOT IN ('root', 'mysql.sys')
                     """)

    with engine.connect() as conn:
        results = conn.execute(query).fetchall()

    if results:
        accounts = ", ".join(row[0] for row in results)
        return Finding (
            severity = Severity.MEDIUM,
            title = "Users with excessive privileges",
            description = f"These users have broad privileges across many tables: {accounts}. "
                          f"Apply the principle of least privilege — grant only what's needed.",
            passed = False,
        )

    return Finding (
        severity = Severity.INFO,
        title = "Privilege check",
        description = "No users with excessive privileges detected.",
        passed = True,
    )