import psycopg2
from urllib.parse import urlparse
import os


def main():
    db_url = urlparse(os.environ["DATABASE_URL"])

    conn = psycopg2.connect(
        database=db_url.path[1:],
        user=db_url.username,
        password=db_url.password,
        host=db_url.hostname,
        port=db_url.port,
    )

    cursor = conn.cursor()

    cursor.execute(
        """CREATE TABLE IF NOT EXISTS Users (
                     Username varchar(255) NOT NULL UNIQUE,
                     Password varchar(255) NOT NULL
                     );"""
    )

    conn.commit()
    conn.close()
    cursor.close()


if __name__ == "__main__":
    main()
