import csv
import json
from contextlib import closing
import os
import sqlite3
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'survival' / 'scripts' / 'records.py'

class RecordsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.tmp.cleanup)
        if os.name == 'nt':
            who = subprocess.run(['whoami', '/user', '/fo', 'csv', '/nh'], capture_output=True, text=True, check=True)
            sid = next(csv.reader([who.stdout.strip()]))[1]
            subprocess.run(['icacls', self.tmp.name, '/inheritance:r', '/grant:r', f'*{sid}:(OI)(CI)F', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F'], capture_output=True, check=True)
        self.db = Path(self.tmp.name) / 'private' / 'records.sqlite3'

    def run_cli(self, action, data=None, *extra):
        return subprocess.run([sys.executable, str(SCRIPT), '--db', str(self.db), action, *extra], input=json.dumps(data or {}, ensure_ascii=False), text=True, encoding='utf-8', capture_output=True)

    def test_missing_read_does_not_create_database(self):
        result = self.run_cli('list')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.db.exists())

    def test_save_read_update_delete(self):
        result = self.run_cli('add', {'summary':'事实一','facts':'未获确认','next_step':'核对'})
        self.assertEqual(result.returncode, 0, result.stderr)
        rid = json.loads(result.stdout)['id']
        result = self.run_cli('get', {'id':rid})
        self.assertEqual(json.loads(result.stdout)['summary'], '事实一')
        result = self.run_cli('update', {'id':rid,'summary':'已更正'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.run_cli('get', {'id':rid}).stdout)['summary'], '已更正')
        self.assertEqual(self.run_cli('update', {'id':rid,'facts':None}).returncode, 0)
        self.assertIsNone(json.loads(self.run_cli('get', {'id':rid}).stdout)['facts'])
        self.assertEqual(self.run_cli('delete', {'id':rid}).returncode, 0)
        self.assertNotEqual(self.run_cli('get', {'id':rid}).returncode, 0)

    def test_backup_export_and_no_overwrite(self):
        self.assertEqual(self.run_cli('add', {'summary':'测试记录'}).returncode, 0)
        backup = str(Path(self.tmp.name) / 'copy.sqlite3')
        output = str(Path(self.tmp.name) / 'copy.json')
        result = self.run_cli('backup', {'destination':backup})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(Path(backup).exists())
        with closing(sqlite3.connect(backup)) as con:
            self.assertEqual(con.execute('SELECT summary FROM records').fetchone()[0], '测试记录')
        result = self.run_cli('export', {'destination':output})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(Path(output).read_text(encoding='utf-8'))[0]['summary'], '测试记录')
        self.assertNotEqual(self.run_cli('backup', {'destination':backup}).returncode, 0)

    def test_reject_unknown_fields(self):
        result = self.run_cli('add', {'summary':'a','password':'secret'})
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('secret', result.stdout + result.stderr)
        self.assertFalse(self.db.exists())

    def test_relative_destination_rejected_without_file(self):
        self.assertEqual(self.run_cli('add', {'summary':'example'}).returncode, 0)
        result = self.run_cli('export', {'destination':'relative.json'})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((ROOT / 'relative.json').exists())

    def test_bad_update_leaves_original_record(self):
        added = self.run_cli('add', {'summary':'before'})
        rid = json.loads(added.stdout)['id']
        result = self.run_cli('update', {'id':rid,'password':'example'})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(self.run_cli('get', {'id':rid}).stdout)['summary'], 'before')

    def test_locked_database_reports_failure_without_changing_record(self):
        added = self.run_cli('add', {'summary':'before'})
        rid = json.loads(added.stdout)['id']
        with closing(sqlite3.connect(self.db)) as con:
            con.execute('BEGIN EXCLUSIVE')
            result = self.run_cli('update', {'id':rid,'summary':'after'})
            self.assertNotEqual(result.returncode, 0)
            con.rollback()
        self.assertEqual(json.loads(self.run_cli('get', {'id':rid}).stdout)['summary'], 'before')

    @unittest.skipUnless(os.name == 'nt', 'Windows ACL test')
    def test_shared_directory_acl_blocks_write(self):
        subprocess.run(['icacls', self.tmp.name, '/grant', '*S-1-1-0:(OI)(CI)R'], capture_output=True, check=True)
        result = self.run_cli('add', {'summary':'synthetic'})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.db.exists())

    def test_redirected_path_is_rejected(self):
        link = Path(self.tmp.name) / 'redirect'
        real = Path(self.tmp.name) / 'actual'
        real.mkdir()
        try:
            link.symlink_to(real, target_is_directory=True)
        except OSError:
            self.skipTest('system does not allow symlink creation')
        result = subprocess.run([sys.executable, str(SCRIPT), '--db', str(link / 'data.sqlite3'), 'add'], input=json.dumps({'summary':'synthetic'}), text=True, encoding='utf-8', capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((real / 'data.sqlite3').exists())

    def test_default_database_is_within_authorized_working_directory(self):
        result = subprocess.run([sys.executable, str(SCRIPT), 'add'], input=json.dumps({'summary':'synthetic'}), cwd=self.tmp.name, text=True, encoding='utf-8', capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(Path(json.loads(result.stdout)['path']), Path(self.tmp.name) / 'survival-records' / 'records.sqlite3')

if __name__ == '__main__':
    unittest.main()
