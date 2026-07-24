#!/usr/bin/env python3
"""
postgres backup/restore with optional aes encryption + telegram upload.
designed for cronjobs - no interactive prompts, logs everything.
use --no-encrypt / --no-decrypt to skip encryption.
"""

import argparse
import subprocess
import sys
import os
import hashlib
import logging
import requests
from datetime import datetime, timedelta
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv
import dropbox
from dropbox.files import WriteMode
from dropbox.exceptions import ApiError

# load .env from script directory
SCRIPT_DIR = Path(__file__).parent.resolve()
load_dotenv(SCRIPT_DIR / ".env")

# ============ CONFIG  ============
ENCRYPTION_PASSWORD = os.environ.get("ENCRYPTION_PASSWORD", os.environ.get("DB_PASSWORD", "your-secret-password-here"))

# where backups go (relative to script dir, or set absolute path for cron)
SCRIPT_DIR = Path(__file__).parent.resolve()
BACKUP_DIR = os.environ.get("BACKUP_DIR", str(SCRIPT_DIR / "backups"))

# dropbox config -- use refresh token, not short-lived access token
# get these from https://www.dropbox.com/developers/apps
DROPBOX_APP_KEY = os.environ.get("DROPBOX_APP_KEY", "")
DROPBOX_APP_SECRET = os.environ.get("DROPBOX_APP_SECRET", "")
DROPBOX_REFRESH_TOKEN = os.environ.get("DROPBOX_REFRESH_TOKEN", "")
DROPBOX_FOLDER = os.environ.get("DROPBOX_FOLDER", "/backups")
LOCAL_RETENTION_DAYS = os.environ.get("LOCAL_RETENTION_DAYS", "")
DROPBOX_RETENTION_DAYS = os.environ.get("DROPBOX_RETENTION_DAYS", "")

# telegram config (leave empty to disable)
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
TELEGRAM_API_ID = os.environ.get("TELEGRAM_API_ID", "")
TELEGRAM_API_HASH = os.environ.get("TELEGRAM_API_HASH", "")
# optional mtproto proxy (only works if api_id/hash are set)
MTPROTO_PROXY_HOST = os.environ.get("MTPROTO_PROXY_HOST", "")
MTPROTO_PROXY_PORT = os.environ.get("MTPROTO_PROXY_PORT", "")
MTPROTO_PROXY_SECRET = os.environ.get("MTPROTO_PROXY_SECRET", "")
# tor switch
USE_TOR = os.environ.get("USE_TOR", "").lower() == "true"

# postgres defaults
PG_HOST = os.environ.get("DB_HOST", "localhost")
PG_PORT = os.environ.get("DB_PORT", "5432")
PG_USER = os.environ.get("DB_USER", "postgres")
PG_PASSWORD = os.environ.get("DB_PASSWORD", "")
PG_DATABASE = os.environ.get("DB_NAME", "")
PG_SSLMODE = os.environ.get("DB_SSLMODE", "prefer")  # set to 'require' for cloud dbs
# =========================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger(__name__)


def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000, dklen=32)


def encrypt_data(data: bytes, password: str) -> bytes:
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)
    
    pad_len = 16 - (len(data) % 16)
    padded_data = data + bytes([pad_len] * pad_len)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return salt + iv + ciphertext


def decrypt_data(encrypted: bytes, password: str) -> bytes:
    salt = encrypted[:16]
    iv = encrypted[16:32]
    ciphertext = encrypted[32:]
    
    key = derive_key(password, salt)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    pad_len = padded_data[-1]
    return padded_data[:-pad_len]


def run_cmd(cmd: list[str], env: dict = None, input_data: bytes = None) -> subprocess.CompletedProcess:
    merged_env = {**os.environ, **(env or {})}
    return subprocess.run(cmd, env=merged_env, input=input_data, capture_output=True)


def get_pg_env(host: str, port: str, user: str, password: str, sslmode: str = None) -> dict:
    env = {
        "PGHOST": host,
        "PGPORT": port,
        "PGUSER": user,
        "PGPASSWORD": password,
    }
    if sslmode:
        env["PGSSLMODE"] = sslmode
    return env


def _get_telethon_client():
    from telethon.sync import TelegramClient
    from telethon.sessions import StringSession
    from telethon.network import ConnectionTcpMTProxyRandomizedIntermediate
    
    proxy = None
    connection = None
    if USE_TOR:
        try:
            import socks
            proxy = (socks.SOCKS5, '127.0.0.1', 9050)
        except ImportError:
            log.error("PySocks not installed. run: pip install pysocks")
            raise
    elif MTPROTO_PROXY_HOST and MTPROTO_PROXY_PORT and MTPROTO_PROXY_SECRET:
        proxy = (MTPROTO_PROXY_HOST, int(MTPROTO_PROXY_PORT), MTPROTO_PROXY_SECRET)
        connection = ConnectionTcpMTProxyRandomizedIntermediate
        
    kwargs = {}
    if proxy:
        kwargs["proxy"] = proxy
        kwargs["connection"] = connection
        
    return TelegramClient(StringSession(), int(TELEGRAM_API_ID), TELEGRAM_API_HASH, **kwargs)


def send_telegram_file(filepath: str, caption: str = "") -> bool:
    """upload file to telegram. returns True on success."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        log.info("telegram not configured, skipping upload")
        return False
        
    chat_id = TELEGRAM_CHAT_ID
    try:
        chat_id = int(chat_id)
    except ValueError:
        pass

    if TELEGRAM_API_ID and TELEGRAM_API_HASH:
        log.info("using mtproto for file upload...")
        try:
            client = _get_telethon_client()
            client.start(bot_token=TELEGRAM_BOT_TOKEN)
            client.send_file(chat_id, filepath, caption=caption)
            client.disconnect()
            log.info("uploaded to telegram (mtproto) successfully")
            return True
        except ImportError:
            log.error("telethon not installed. run: pip install telethon")
            return False
        except Exception as e:
            log.error(f"mtproto upload error: {e}")
            return False

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"
    
    proxies = None
    if USE_TOR:
        proxies = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}
    
    try:
        with open(filepath, "rb") as f:
            files = {"document": (os.path.basename(filepath), f)}
            data = {"chat_id": TELEGRAM_CHAT_ID, "caption": caption[:1024]}  # telegram caption limit
            
            response = requests.post(url, files=files, data=data, timeout=300, proxies=proxies)
            
            if response.status_code == 200:
                log.info("uploaded to telegram successfully")
                return True
            else:
                log.error(f"telegram upload failed: {response.text}")
                return False
    except Exception as e:
        log.error(f"telegram upload error: {e}")
        return False


def send_telegram_message(message: str) -> bool:
    """send a text message to telegram."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False
        
    chat_id = TELEGRAM_CHAT_ID
    try:
        chat_id = int(chat_id)
    except ValueError:
        pass

    if TELEGRAM_API_ID and TELEGRAM_API_HASH:
        try:
            client = _get_telethon_client()
            client.start(bot_token=TELEGRAM_BOT_TOKEN)
            client.send_message(chat_id, message, parse_mode="html")
            client.disconnect()
            return True
        except Exception:
            return False
            
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    
    proxies = None
    if USE_TOR:
        proxies = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}
    
    try:
        response = requests.post(url, data={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "HTML"
        }, timeout=30, proxies=proxies)
        return response.status_code == 200
    except Exception:
        return False


def check_connections(args) -> bool:
    """test postgres and telegram connections."""
    success = True
    log.info("testing postgres connection...")
    pg_env = get_pg_env(args.host, args.port, args.user, args.password, args.sslmode)
    
    cmd = ["pg_isready", "-h", args.host, "-p", str(args.port), "-U", args.user]
    result = run_cmd(cmd, env=pg_env)
    
    if result.returncode == 0:
        log.info("postgres connection successful")
    else:
        err_out = result.stderr.decode().strip() or result.stdout.decode().strip()
        log.error(f"postgres connection failed: {err_out}")
        success = False
        
    log.info("testing telegram connection...")
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        log.info("telegram not configured (skipping)")
    else:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getMe"
        proxies = None
        if USE_TOR:
            proxies = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}
            
        try:
            response = requests.get(url, timeout=10, proxies=proxies)
            if response.status_code == 200:
                log.info("telegram bot token valid")
                msg_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
                msg_response = requests.post(msg_url, data={
                    "chat_id": TELEGRAM_CHAT_ID,
                    "text": "🛠️ <b>Connection test successful</b>",
                    "parse_mode": "HTML"
                }, timeout=10, proxies=proxies)
                if msg_response.status_code == 200:
                    log.info("telegram message sent successfully")
                else:
                    log.error(f"telegram message failed (check chat ID): {msg_response.text}")
                    success = False
            else:
                log.error(f"telegram bot token invalid: {response.text}")
                success = False
        except Exception as e:
            log.error(f"telegram reachability error: {e}")
            success = False
            
    return success


def run_test(args):
    """run the standalone connection test."""
    if check_connections(args):
        log.info("all tests passed!")
    else:
        log.error("some tests failed")
        sys.exit(1)


def export_db(args):
    """dump postgres db, encrypt, and optionally upload to telegram."""
    pg_env = get_pg_env(args.host, args.port, args.user, args.password, args.sslmode)
    
    # ensure backup dir exists
    backup_dir = Path(args.backup_dir)
    backup_dir.mkdir(parents=True, exist_ok=True)
    
    # generate output path if not specified
    if args.output:
        output_path = Path(args.output)
        if not output_path.is_absolute():
            output_path = backup_dir / output_path
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = backup_dir / f"{args.database}_{timestamp}.enc"
    
    log.info(f"dumping database '{args.database}'...")
    dump_cmd = ["pg_dump", "-Fc", args.database]
    dump_result = run_cmd(dump_cmd, env=pg_env)
    
    if dump_result.returncode != 0:
        error_msg = f"pg_dump failed: {dump_result.stderr.decode()}"
        log.error(error_msg)
        send_telegram_message(f"❌ <b>Backup Failed</b>\n\n<b>Database:</b> {args.database}\n<b>Host:</b> {args.host}:{args.port}\n<b>User:</b> {args.user}\n<b>Error:</b> {error_msg[:500]}")
        sys.exit(1)
    
    # encrypt if enabled
    if args.no_encrypt:
        log.info("saving dump (no encryption)...")
        data_to_write = dump_result.stdout
    else:
        log.info("encrypting dump...")
        data_to_write = encrypt_data(dump_result.stdout, args.encrypt_key)
    
    with open(output_path, "wb") as f:
        f.write(data_to_write)
    
    file_size = os.path.getsize(output_path)
    size_mb = file_size / 1024 / 1024
    
    log.info(f"backup saved to: {output_path} ({size_mb:.2f} MB)")
    
    # upload to telegram if configured
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        conn_info = f"🔗 {args.user}@{args.host}:{args.port}"
        encrypted_status = "🔓 unencrypted" if args.no_encrypt else "🔒 encrypted"
        caption = f"📦 {args.database} backup\n{conn_info}\n📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n💾 {size_mb:.2f} MB\n{encrypted_status}"
        
        # telegram file size limit is 50MB for bots (http api)
        is_mtproto = bool(TELEGRAM_API_ID and TELEGRAM_API_HASH)
        if not is_mtproto and file_size > 50 * 1024 * 1024:
            log.warning("file too large for telegram (>50MB), sending notification only")
            send_telegram_message(f"✅ <b>Backup Complete</b>\n\n<b>Database:</b> {args.database}\n<b>Host:</b> {args.host}:{args.port}\n<b>User:</b> {args.user}\n<b>SSL:</b> {args.sslmode}\n<b>Size:</b> {size_mb:.2f} MB\n<b>Status:</b> {encrypted_status}\n<b>Path:</b> {output_path}\n\n⚠️ File too large for Telegram upload")
        else:
            send_telegram_file(str(output_path), caption)
            
    # upload to dropbox if configured
    if DROPBOX_REFRESH_TOKEN:
        upload_to_dropbox(str(output_path), args.dropbox_folder)
    
    # cleanup old backups if retention is set
    if args.retain:
        cleanup_old_backups(backup_dir, args.database, args.retain)
    if args.local_retention_days:
        cleanup_local_backups_by_days(backup_dir, args.database, args.local_retention_days)
    if DROPBOX_REFRESH_TOKEN and args.dropbox_retention_days:
        cleanup_dropbox_backups_by_days(args.dropbox_folder, args.database, args.dropbox_retention_days)
    
    log.info("done!")


def cleanup_old_backups(backup_dir: Path, database: str, retain: int):
    """keep only the N most recent backups for a database."""
    pattern = f"{database}_*.enc"
    backups = sorted(backup_dir.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
    
    for old_backup in backups[retain:]:
        log.info(f"removing old backup: {old_backup.name}")
        old_backup.unlink()


def cleanup_local_backups_by_days(backup_dir: Path, database: str, days: int):
    """delete local backups older than N days."""
    pattern = f"{database}_*.enc"
    cutoff = datetime.now() - timedelta(days=days)
    
    for backup_file in backup_dir.glob(pattern):
        mtime = datetime.fromtimestamp(backup_file.stat().st_mtime)
        if mtime < cutoff:
            log.info(f"removing old local backup: {backup_file.name}")
            backup_file.unlink()


def get_dropbox_client() -> "dropbox.Dropbox | None":
    """build a dropbox client using refresh token -- never expires unless manually revoked."""
    if not DROPBOX_REFRESH_TOKEN or not DROPBOX_APP_KEY or not DROPBOX_APP_SECRET:
        return None
    return dropbox.Dropbox(
        oauth2_refresh_token=DROPBOX_REFRESH_TOKEN,
        app_key=DROPBOX_APP_KEY,
        app_secret=DROPBOX_APP_SECRET,
    )


def upload_to_dropbox(local_path: str, dropbox_folder: str) -> bool:
    """upload file to dropbox. token refresh is handled automatically by the sdk."""
    dbx = get_dropbox_client()
    if not dbx:
        return False
    try:
        filename = os.path.basename(local_path)
        db_folder = dropbox_folder.rstrip('/')
        if not db_folder.startswith('/'):
            db_folder = '/' + db_folder
        dropbox_path = f"{db_folder}/{filename}"
        
        with open(local_path, "rb") as f:
            log.info(f"uploading {local_path} to dropbox ({dropbox_path})...")
            meta = dbx.files_upload(
                f.read(),
                dropbox_path,
                mode=WriteMode("overwrite")
            )
            log.info(f"uploaded to dropbox successfully: {meta.path_display}")
            return True
    except FileNotFoundError:
        log.error(f"dropbox upload error: local file '{local_path}' not found")
    except ApiError as err:
        log.error(f"dropbox api error: {err}")
    except Exception as e:
        log.error(f"dropbox upload error: {e}")
    return False


def cleanup_dropbox_backups_by_days(dropbox_folder: str, database: str, days: int):
    """delete dropbox backups older than N days."""
    dbx = get_dropbox_client()
    if not dbx:
        return
    try:
        db_folder = dropbox_folder.rstrip('/')
        if not db_folder.startswith('/'):
            db_folder = '/' + db_folder
            
        cutoff = datetime.now() - timedelta(days=days)
        result = dbx.files_list_folder(db_folder)
        
        while True:
            for entry in result.entries:
                if isinstance(entry, dropbox.files.FileMetadata):
                    if entry.name.startswith(f"{database}_") and entry.name.endswith(".enc"):
                        if entry.client_modified < cutoff:
                            log.info(f"removing old dropbox backup: {entry.path_display}")
                            dbx.files_delete_v2(entry.path_display)
            
            if not result.has_more:
                break
            result = dbx.files_list_folder_continue(result.cursor)
            
    except ApiError as err:
        log.error(f"dropbox api error during cleanup: {err}")
    except Exception as e:
        log.error(f"dropbox cleanup error: {e}")


def import_db(args):
    """decrypt backup and restore to postgres, nuking the target db first."""
    pg_env = get_pg_env(args.host, args.port, args.user, args.password, args.sslmode)
    
    input_path = Path(args.input)
    if not input_path.exists():
        log.error(f"backup file not found: {input_path}")
        sys.exit(1)
    
    log.info(f"reading backup '{input_path}'...")
    with open(input_path, "rb") as f:
        file_data = f.read()
    
    # decrypt if needed
    if args.no_decrypt:
        log.info("using raw dump (no decryption)...")
        restore_data = file_data
    else:
        log.info("decrypting backup...")
        try:
            restore_data = decrypt_data(file_data, args.encrypt_key)
        except Exception as e:
            log.error(f"decryption failed (wrong password or not encrypted?): {e}")
            sys.exit(1)
    
    log.info(f"wiping database '{args.database}'...")
    
    # for managed databases (aiven, neon, etc) we can't drop the database itself
    # instead, drop all tables in the public schema
    drop_tables_sql = """
    DO $$ 
    DECLARE r RECORD;
    BEGIN
        FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = 'public') LOOP
            EXECUTE 'DROP TABLE IF EXISTS public.' || quote_ident(r.tablename) || ' CASCADE';
        END LOOP;
    END $$;
    """
    drop_cmd = ["psql", "-d", args.database, "-c", drop_tables_sql]
    drop_result = run_cmd(drop_cmd, env=pg_env)
    
    if drop_result.returncode != 0:
        log.warning(f"drop tables warning: {drop_result.stderr.decode()}")
    
    log.info("restoring database...")
    # --clean drops objects before recreating, --if-exists prevents errors on missing objects
    restore_cmd = ["pg_restore", "-d", args.database, "--no-owner", "--no-privileges", "--clean", "--if-exists"]
    
    restore_proc = subprocess.Popen(
        restore_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, **pg_env}
    )
    
    stdout, stderr = restore_proc.communicate(input=restore_data)
    
    if restore_proc.returncode != 0:
        stderr_text = stderr.decode()
        # pg_restore often returns non-zero for non-fatal warnings
        if "ERROR" in stderr_text and "does not exist" not in stderr_text:
            log.error(f"pg_restore failed: {stderr_text}")
            sys.exit(1)
        else:
            log.warning(f"pg_restore completed with warnings")
    
    log.info(f"database '{args.database}' restored successfully")


def main():
    parser = argparse.ArgumentParser(
        description="postgres backup/restore with encryption + telegram",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # export with defaults from config
  %(prog)s export
  
  # export specific database
  %(prog)s export -d mydb
  
  # export and keep only last 7 backups
  %(prog)s export -d mydb --retain 7
  
  # import from backup
  %(prog)s import -d mydb -i /path/to/backup.enc

cronjob example (daily at 3am, keep 7 days):
  0 3 * * * /usr/bin/python3 /path/to/pg_backup.py export --retain 7
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    def add_common_args(p):
        p.add_argument("-d", "--database", default=PG_DATABASE, help=f"database name (default: {PG_DATABASE or 'not set'})")
        p.add_argument("-H", "--host", default=PG_HOST, help=f"postgres host (default: {PG_HOST})")
        p.add_argument("-P", "--port", default=PG_PORT, help=f"postgres port (default: {PG_PORT})")
        p.add_argument("-U", "--user", default=PG_USER, help=f"postgres user (default: {PG_USER})")
        p.add_argument("-W", "--password", default=PG_PASSWORD, help="postgres password")
        p.add_argument("-S", "--sslmode", default=PG_SSLMODE, help=f"ssl mode (default: {PG_SSLMODE})")
    
    export_parser = subparsers.add_parser("export", help="export database (optionally encrypt)")
    add_common_args(export_parser)
    export_parser.add_argument("-o", "--output", help="output filename (optional)")
    export_parser.add_argument("-b", "--backup-dir", default=BACKUP_DIR, help=f"backup directory (default: {BACKUP_DIR})")
    export_parser.add_argument("--retain", type=int, help="keep only N most recent backups")
    export_parser.add_argument("--local-retention-days", type=int, default=int(LOCAL_RETENTION_DAYS) if LOCAL_RETENTION_DAYS else None, help="delete local backups older than N days")
    export_parser.add_argument("--dropbox-folder", default=DROPBOX_FOLDER, help="dropbox destination folder")
    export_parser.add_argument("--dropbox-retention-days", type=int, default=int(DROPBOX_RETENTION_DAYS) if DROPBOX_RETENTION_DAYS else None, help="delete dropbox backups older than N days")
    export_parser.add_argument("--no-encrypt", action="store_true", help="skip encryption (save raw pg_dump)")
    export_parser.add_argument("-k", "--encrypt-key", default=ENCRYPTION_PASSWORD, help="override encryption password")
    
    import_parser = subparsers.add_parser("import", help="import database (optionally decrypt, wipes target!)")
    add_common_args(import_parser)
    import_parser.add_argument("-i", "--input", required=True, help="backup file to restore")
    import_parser.add_argument("--no-decrypt", action="store_true", help="skip decryption (raw pg_dump file)")
    import_parser.add_argument("-k", "--encrypt-key", default=ENCRYPTION_PASSWORD, help="override encryption password")
    
    test_parser = subparsers.add_parser("test", help="test connections to postgres and telegram")
    add_common_args(test_parser)
    
    args = parser.parse_args()
    
    if not args.password:
        args.password = os.environ.get("PGPASSWORD", PG_PASSWORD)
    
    if args.command != "test" and not args.database:
        log.error("database name required. set PG_DATABASE in config or use -d flag")
        sys.exit(1)
    
    if args.command == "export":
        export_db(args)
    elif args.command == "import":
        import_db(args)
    elif args.command == "test":
        run_test(args)


if __name__ == "__main__":
    main()
