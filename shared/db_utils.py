"""
shared/db_utils.py  —  SQLite 資料庫工具

對 SQLite 的簡單封裝，讓各服務可以用統一的方式操作資料庫。
每個服務有自己獨立的 .db 檔案。
"""

import sqlite3
import os
from contextlib import contextmanager


class Database:
    """
    SQLite 資料庫包裝器。
    支援自動建立資料庫目錄、執行 DDL/DML、查詢等操作。
    """

    def __init__(self, db_path: str):
        """
        初始化資料庫連線。
        db_path：資料庫檔案路徑（若目錄不存在會自動建立）。
        """
        self.db_path = db_path
        # 確保目錄存在
        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

    @contextmanager
    def _get_conn(self):
        """取得資料庫連線（context manager，自動 commit/rollback）"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # 讓查詢結果可用欄位名稱存取
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def execute(self, sql: str, params: tuple = ()) -> None:
        """執行 DDL 或 DML（CREATE TABLE、INSERT、UPDATE、DELETE）"""
        with self._get_conn() as conn:
            conn.execute(sql, params)

    def executemany(self, sql: str, params_list: list) -> None:
        """批次執行 DML"""
        with self._get_conn() as conn:
            conn.executemany(sql, params_list)

    def fetchone(self, sql: str, params: tuple = ()) -> dict | None:
        """查詢單筆記錄，回傳 dict 或 None"""
        with self._get_conn() as conn:
            row = conn.execute(sql, params).fetchone()
            return dict(row) if row else None

    def fetchall(self, sql: str, params: tuple = ()) -> list[dict]:
        """查詢多筆記錄，回傳 list of dict"""
        with self._get_conn() as conn:
            rows = conn.execute(sql, params).fetchall()
            return [dict(row) for row in rows]

    def exists(self, sql: str, params: tuple = ()) -> bool:
        """檢查是否存在符合條件的記錄"""
        return self.fetchone(sql, params) is not None

    def count(self, table: str, where: str = "", params: tuple = ()) -> int:
        """計算符合條件的記錄數"""
        sql = f"SELECT COUNT(*) as cnt FROM {table}"
        if where:
            sql += f" WHERE {where}"
        row = self.fetchone(sql, params)
        return row["cnt"] if row else 0
