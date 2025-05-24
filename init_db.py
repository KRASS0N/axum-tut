from pathlib import Path
from urllib.parse import urlparse
import os
import psycopg2
from python_mods.colors import bcolors


def main():
    print("Initializing database and related content directories...")

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
                     Username varchar(255) NOT NULL UNIQUE PRIMARY KEY,
                     Password varchar(255) NOT NULL,
                     Avatar varchar(255)
                     );"""
    )

    cursor.execute(
        """CREATE TABLE IF NOT EXISTS Works (
                     WorkID SERIAL PRIMARY KEY,
                     Author varchar(255) REFERENCES Users(Username)
                     ON DELETE SET NULL ON UPDATE CASCADE
                     );"""
    )

    cursor.execute(
        """CREATE TABLE IF NOT EXISTS Chapters (
                     ChapterID SERIAL PRIMARY KEY,
                     WorkID INTEGER NOT NULL REFERENCES Works(WorkID)
                     ON DELETE CASCADE ON UPDATE CASCADE
                     );"""
    )

    cursor.execute(
        """CREATE TABLE IF NOT EXISTS Contributions (
                     ContribID SERIAL PRIMARY KEY,
                     ChapterID INTEGER NOT NULL REFERENCES Chapters(ChapterID)
                     ON DELETE CASCADE ON UPDATE CASCADE,
                     PrevID INTEGER,
                     NextID INTEGER
                     );"""
    )

    conn.commit()
    conn.close()
    cursor.close()

    Path("static/avatars").mkdir(exist_ok=True)

    print(bcolors.OKGREEN + "Success!" + bcolors.ENDC)


if __name__ == "__main__":
    main()
