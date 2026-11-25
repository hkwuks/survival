"""Local, user-invoked SQLite records; request data is read from stdin as JSON."""
import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys


FIELDS = ('summary', 'facts', 'uncertainties', 'next_step', 'source')
SECRET = re.compile(r'(?i)(password|passwd|api[_-]?key|access[_-]?token|secret|cookie|私钥|密码|令牌)\s*[:=：]')


def default_db():
    """Candidate under the current authorized project; never probe other roots."""
    return Path.cwd() / 'survival-records' / 'records.sqlite3'

def parse_data():
    obj = json.load(sys.stdin)
    if not isinstance(obj, dict):
        raise ValueError('输入必须是 JSON 对象')
    return obj


def validate(data, permitted, required=()):
    if set(data) - set(permitted) or any(k not in data for k in required):
        raise ValueError('字段不符合操作要求')
    for key, value in data.items():
        if key == 'id':
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError('id 必须是正整数')
        elif value is None and key in FIELDS and key != 'summary':
            continue
        elif not isinstance(value, str) or not value.strip():
            raise ValueError('字段必须是非空字符串')
        elif key in FIELDS and SECRET.search(value):
            raise ValueError('疑似凭据，拒绝保存')


def check_private_directory(path):
    """Conservatively reject Windows directories with untrusted allow ACEs."""
    existing = path
    while not existing.exists():
        if existing == existing.parent:
            raise ValueError('无法确认目录权限')
        existing = existing.parent
    if os.name != 'nt':
        info = existing.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError('目录或数据库权限不受当前用户独占控制')
        return
    script = r'''$ErrorActionPreference="Stop"
$p=$env:SURVIVAL_CHECK_DIRECTORY
$allowed=@([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value,"S-1-5-18","S-1-5-32-544")
$acl=if ([System.IO.Directory]::Exists($p)) { [System.IO.Directory]::GetAccessControl($p) } else { [System.IO.File]::GetAccessControl($p) }
$owner=(New-Object System.Security.Principal.NTAccount($acl.Owner)).Translate([System.Security.Principal.SecurityIdentifier]).Value
if ($owner -eq $allowed[0]) { $allowed += 'S-1-3-4' }
foreach($rule in $acl.Access) {
  if ($rule.AccessControlType -eq "Allow") {
    $sid=$rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
    if ($sid -notin $allowed) { exit 3 }
  }
}
exit 0'''
    env = dict(os.environ, SURVIVAL_CHECK_DIRECTORY=str(existing))
    try:
        result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError('无法核实 Windows 目录访问权限，未执行操作') from exc
    if result.returncode:
        raise ValueError('Windows 目录权限包含未验证主体或无法核实；请选择权限受控的位置')

def reject_redirects(path):
    if not path.is_absolute():
        raise ValueError('路径必须是绝对路径')
    if os.path.normcase(str(path.resolve(strict=False))) != os.path.normcase(os.path.abspath(str(path))):
        raise ValueError('路径含重定向或链接；请选择实际授权位置')

def open_db(path, create=False):
    reject_redirects(path)
    if not create and not path.is_file():
        raise ValueError('数据库不存在；未创建文件')
    check_private_directory(path.parent)
    if path.exists():
        check_private_directory(path)
    if create:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not path.exists():
            fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
    con = sqlite3.connect(str(path), timeout=2)
    con.row_factory = sqlite3.Row
    if create:
        con.execute('CREATE TABLE IF NOT EXISTS records (id INTEGER PRIMARY KEY, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, summary TEXT NOT NULL, facts TEXT, uncertainties TEXT, next_step TEXT, source TEXT)')
        con.commit()
    return con


def reserved_file(dest):
    path = Path(dest)
    reject_redirects(path)
    if not path.parent.is_dir():
        raise ValueError('目标目录不存在')
    check_private_directory(path.parent)
    fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    return path, fd


def main():
    parser = argparse.ArgumentParser(description='操作经用户授权的本地记录；JSON 从标准输入读取。')
    parser.add_argument('--db', help='获授权的数据库绝对路径')
    parser.add_argument('action', choices=('add', 'list', 'get', 'update', 'delete', 'export', 'backup'))
    args = parser.parse_args()
    data = parse_data()
    action = args.action
    permitted = {'add': FIELDS, 'list': (), 'get': ('id',), 'update': ('id',) + FIELDS, 'delete': ('id',), 'export': ('destination',), 'backup': ('destination',)}
    required = {'add': ('summary',), 'get': ('id',), 'update': ('id',), 'delete': ('id',), 'export': ('destination',), 'backup': ('destination',)}
    validate(data, permitted[action], required.get(action, ()))
    if action == 'update' and not any(k in data for k in FIELDS):
        raise ValueError('没有需要更新的字段')
    path = Path(args.db) if args.db else default_db()
    con = open_db(path, create=action == 'add')
    try:
        if action == 'add':
            cols = [k for k in FIELDS if k in data]
            cur = con.execute('INSERT INTO records (' + ','.join(cols) + ') VALUES (' + ','.join('?' for _ in cols) + ')', [data[k] for k in cols])
            con.commit()
            result = {'id': cur.lastrowid, 'path': str(path)}
        elif action == 'list':
            result = [dict(row) for row in con.execute('SELECT * FROM records ORDER BY id')]
        elif action == 'get':
            row = con.execute('SELECT * FROM records WHERE id=?', (data['id'],)).fetchone()
            if row is None:
                raise ValueError('记录不存在')
            result = dict(row)
        elif action == 'update':
            cols = [k for k in FIELDS if k in data]
            cur = con.execute('UPDATE records SET ' + ','.join(k + '=?' for k in cols) + ',updated_at=CURRENT_TIMESTAMP WHERE id=?', [data[k] for k in cols] + [data['id']])
            if not cur.rowcount:
                raise ValueError('记录不存在')
            con.commit()
            result = {'updated': data['id']}
        elif action == 'delete':
            cur = con.execute('DELETE FROM records WHERE id=?', (data['id'],))
            if not cur.rowcount:
                raise ValueError('记录不存在')
            con.commit()
            result = {'deleted': data['id']}
        else:
            dest, fd = reserved_file(data['destination'])
            try:
                if action == 'export':
                    rows = [dict(row) for row in con.execute('SELECT * FROM records ORDER BY id')]
                    with os.fdopen(fd, 'w', encoding='utf-8') as out:
                        fd = None
                        json.dump(rows, out, ensure_ascii=False, indent=2)
                else:
                    os.close(fd)
                    fd = None
                    with closing(sqlite3.connect(str(dest))) as target:
                        con.backup(target)
                result = {'path': str(dest)}
            except BaseException:
                if fd is not None:
                    os.close(fd)
                dest.unlink(missing_ok=True)
                raise
        print(json.dumps(result, ensure_ascii=False))
    finally:
        con.close()


if __name__ == '__main__':
    try:
        sys.stdin.reconfigure(encoding='utf-8')
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
        main()
    except (ValueError, OSError, sqlite3.Error, json.JSONDecodeError) as exc:
        print('操作失败：' + str(exc), file=sys.stderr)
        sys.exit(1)
