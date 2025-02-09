import queue
from typing import Tuple

import pymysql
from decouple import config
from pymysql import Connection
from pymysql.cursors import Cursor

conn_queue = queue.Queue()
max_connections = int(config("MAX_DB_CONNECTIONS", cast=int, default=5))
salt = bytes(str(config("SALT", cast=str)), "utf-8")


def get_connection() -> Tuple[Connection, Cursor]:
    if conn_queue.qsize() == 0:
        conn = create_connection()
        cursor = conn.cursor()
        return conn, cursor
    else:
        conn = conn_queue.get()
        cursor = conn.cursor()
        return conn, cursor


def release_connection(connection: Connection, cursor: Cursor):
    cursor.close()

    if conn_queue.qsize() < max_connections:
        conn_queue.put(connection)
    else:
        close_connection(connection)


def create_connection():
    return pymysql.connect(host="localhost", user="root", database="nextgensec_pms")


def close_connection(connection: Connection):
    connection.close()
