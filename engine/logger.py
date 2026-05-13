# ============================================
# engine/logger.py
# ============================================

import sqlite3

from pathlib import Path

from datetime import datetime

BASE_DIR = Path.home() / "ALVSafe"

DATABASE_DIR = (
    BASE_DIR / "database"
)

DATABASE_DIR.mkdir(
    parents=True,
    exist_ok=True
)

DB_PATH = (
    DATABASE_DIR / "logs.db"
)

# ============================================
# INIT
# ============================================

def init_db():

    conn = sqlite3.connect(
        DB_PATH
    )

    cursor = conn.cursor()

    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS logs (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            event TEXT,

            file TEXT,

            timestamp TEXT
        )
        '''
    )

    conn.commit()

    conn.close()

# ============================================
# LOG EVENT
# ============================================

def log_event(
    event,
    file_path
):

    conn = sqlite3.connect(
        DB_PATH
    )

    cursor = conn.cursor()

    cursor.execute(
        '''
        INSERT INTO logs (
            event,
            file,
            timestamp
        )
        VALUES (?, ?, ?)
        ''',
        (
            event,
            file_path,
            datetime.now().strftime(
                '%Y-%m-%d %H:%M:%S'
            )
        )
    )

    conn.commit()

    conn.close()

# ============================================
# INIT DATABASE
# ============================================

init_db()