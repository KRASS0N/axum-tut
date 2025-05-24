from pathlib import Path
from urllib.parse import urlparse
import os
import psycopg2
from python_mods.colors import bcolors
from shutil import rmtree


def main():
    keypress = input(
        bcolors.WARNING
        + "WARNING: This will wipe the ENTIRE database and all associated files.\n"
        + bcolors.ENDC
        + "Is this okay? [y/N]: "
    )
    if keypress.lower() != "y":
        return

    print("Wiping the database...")

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
        "DROP TABLE IF EXISTS Users CASCADE;"
        "DROP TABLE IF EXISTS tower_sessions.session;"
        "DROP TABLE IF EXISTS Works CASCADE;"
        "DROP TABLE IF EXISTS Chapters CASCADE;"
        "DROP TABLE IF EXISTS Contributions;"
    )

    conn.commit()
    conn.close()
    cursor.close()

    rmtree(Path("static/avatars"), ignore_errors=True)

    print(bcolors.OKGREEN + "Success!" + bcolors.ENDC)


if __name__ == "__main__":
    main()
