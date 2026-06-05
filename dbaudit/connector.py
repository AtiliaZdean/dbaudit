# this file handle all db conns
# everything else in the tool calls get_engine() form here
# SQLAlchemy lets us support psql and mysql w/ the same code

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

def build_connection_url(db_type: str, host: str, port: int, db: str, user: str, password: str) -> str:
    """
    build the sqlalchemy connection url for the given database type
    format: dialect+driver://user:password@host:port/dbname
    """
    if db_type == "postgres":
        # psycopg2 is the driver SQLAlchemy uses under the hood for PostgreSQL
        port = port or 5432
        return f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{db}"

    elif db_type == "mysql":
        # pymysql is the driver for MySQL
        port = port or 3306
        return f"mysql+pymysql://{user}:{password}@{host}:{port}/{db}"

    else:
        raise ValueError(f"Unsupported db_type '{db_type}'. Use 'postgres' or 'mysql'.")

def get_engine(db_type: str, host: str, port: int, db: str, user: str, password: str) -> Engine:
    """
    create and return a sqlalchemy engine
    the engine is the starting point for all db operations — think of it as the conn factory. It doesn't open a connection until you use it.
    """
    url = build_connection_url(db_type, host, port, db, user, password)

    # pool_pre_ping=True: tests the connection before using it, avoids stale conns
    engine = create_engine(url, pool_pre_ping=True)
    return engine

def test_connection(engine: Engine) -> bool:
    """
    try to open a real connection and run a trivial query
    returns True if successful, raises an exception if not
    """
    # engine.connect() opens one connection from the pool
    # text() wraps a raw SQL string so sqlalchemy knows its safe to run
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return True