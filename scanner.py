import logging
import os
import time
import uuid
from datetime import datetime
from io import BytesIO
from typing import List, Optional
from fastapi import FastAPI, File, UploadFile, HTTPException, Body, Depends, Header, status
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import psycopg2
from psycopg2.extras import RealDictCursor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="ProjectPlutonium Scanner")
app.mount("/static", StaticFiles(directory="static"), name="static")

DATABASE_CONFIG = {
    "host": os.getenv("DATABASE_HOST", "postgres"),
    "port": int(os.getenv("DATABASE_PORT", "5432")),
    "dbname": os.getenv("POSTGRES_DB", "projectplutonium"),
    "user": os.getenv("POSTGRES_USER", "plutonium_user"),
    "password": os.getenv("POSTGRES_PASSWORD", "secure_password_change_me"),
}

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "password")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "admin-token-123")

class AdminLogin(BaseModel):
    username: str
    password: str


def get_db_conn():
    return psycopg2.connect(**DATABASE_CONFIG)


def wait_for_db(max_retries: int = 12, delay_seconds: int = 5):
    last_error = None
    for attempt in range(1, max_retries + 1):
        try:
            with get_db_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                logger.info("Connected to PostgreSQL on attempt %s", attempt)
                return
        except Exception as exc:
            last_error = exc
            logger.warning("Postgres connection attempt %s/%s failed: %s", attempt, max_retries, exc)
            time.sleep(delay_seconds)
    raise RuntimeError(f"Unable to connect to PostgreSQL after {max_retries} attempts") from last_error


def init_db():
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS objects (
                    id UUID PRIMARY KEY,
                    filename TEXT NOT NULL,
                    content BYTEA NOT NULL,
                    content_type TEXT,
                    scanned BOOLEAN NOT NULL DEFAULT FALSE,
                    scan_result TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
            conn.commit()


@app.on_event("startup")
def startup():
    if os.getenv("DEBUGPY_ENABLED", "true").lower() in ("1", "true", "yes"):
        import debugpy
        debugpy.listen(("0.0.0.0", 5678))
    wait_for_db()
    init_db()


@app.get("/healthz")
def healthz():
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        return {"status": "ok"}
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"database unavailable: {exc}")


def simulate_scan(content: bytes) -> str:
    text = content.decode("utf-8", errors="ignore").lower()
    if "virus" in text:
        return "malicious"
    if len(content) > 10_000_000:
        return "large"
    return "clean"


def verify_admin_token(authorization: Optional[str] = Header(None)):
    if not authorization or authorization != f"Bearer {ADMIN_TOKEN}":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing authorization token")


@app.post("/admin/login")
def admin_login(credentials: AdminLogin):
    if credentials.username == ADMIN_USERNAME and credentials.password == ADMIN_PASSWORD:
        return {"token": ADMIN_TOKEN}
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")


@app.get("/admin/objects")
def admin_list_objects(_auth: str = Depends(verify_admin_token)):
    with get_db_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT id::text, filename, content_type, octet_length(content) AS content_size, scanned, scan_result, created_at FROM objects ORDER BY created_at DESC LIMIT 100"
            )
            return cur.fetchall()


@app.delete("/admin/objects/{object_id}")
def admin_delete_object(object_id: str, _auth: str = Depends(verify_admin_token)):
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM objects WHERE id = %s", (object_id,))
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="object not found")
            conn.commit()
    return {"status": "deleted"}


@app.get("/admin")
def admin_root():
    return RedirectResponse(url="/static/admin/index.html")


@app.get("/admin/login")
def admin_login_root():
    return RedirectResponse(url="/static/admin/login.html")


@app.get("/gallery")
def gallery_root():
    return RedirectResponse(url="/static/gallery.html")


@app.get("/", response_class=HTMLResponse)
def root():
    return FileResponse("static/index.html")


@app.post("/upload")
async def upload(
    files: Optional[List[UploadFile]] = File(None),
    file: Optional[UploadFile] = File(None),
):
    upload_files = []
    if files:
        upload_files.extend(files)
    if file:
        upload_files.append(file)

    if not upload_files:
        raise HTTPException(status_code=400, detail="no files uploaded")

    uploaded = []
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            for upload_file in upload_files:
                content = await upload_file.read()
                if not content:
                    raise HTTPException(status_code=400, detail=f"empty file: {upload_file.filename}")
                scan_result = simulate_scan(content)
                object_id = uuid.uuid4()
                cur.execute(
                    """
                    INSERT INTO objects (id, filename, content, content_type, scanned, scan_result)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (str(object_id), upload_file.filename, psycopg2.Binary(content), upload_file.content_type, True, scan_result),
                )
                uploaded.append(
                    {
                        "id": str(object_id),
                        "filename": upload_file.filename,
                        "scan_result": scan_result,
                        "content_size": len(content),
                    }
                )
            conn.commit()

    return {"uploaded": uploaded}


@app.get("/objects")
def list_objects():
    with get_db_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT id::text, filename, content_type, octet_length(content) AS content_size, scanned, scan_result, created_at FROM objects ORDER BY created_at DESC LIMIT 50"
            )
            rows = cur.fetchall()
            for row in rows:
                row["download_url"] = f"/objects/{row['id']}/download"
            return rows


@app.get("/objects/{object_id}")
def get_object(object_id: str):
    with get_db_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT id::text AS id, filename, content_type, octet_length(content) AS content_size, scanned, scan_result, created_at FROM objects WHERE id = %s",
                (object_id,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="object not found")
            return row

@app.get("/objects/{object_id}/download")
def download_object(object_id: str):
    with get_db_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT filename, content, content_type FROM objects WHERE id = %s",
                (object_id,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="object not found")

    content = row["content"]
    if isinstance(content, memoryview):
        content = content.tobytes()
    content_type = row["content_type"] or "application/octet-stream"
    headers = {"Content-Disposition": f"inline; filename=\"{row['filename']}\""}
    return StreamingResponse(BytesIO(content), media_type=content_type, headers=headers)