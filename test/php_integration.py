"""Run with PHP_BIN=php python3 test/php_integration.py (PHP 8.1+ / pdo_sqlite)."""
import http.cookiejar
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request
import urllib.parse

class PhpIntegration(unittest.TestCase):
    def test_node_credentials_are_not_replaced_with_default(self):
        import sqlite3
        with tempfile.TemporaryDirectory(prefix='seller-migration-') as directory:
            root = Path(directory)
            public = root / 'seller' / 'public'
            shutil.copytree(Path(__file__).resolve().parents[1] / 'public', public)
            database = root / 'database'
            database.mkdir()
            connection = sqlite3.connect(database / 'finance.sqlite')
            connection.executescript("CREATE TABLE credentials(id INTEGER PRIMARY KEY,login TEXT,password_hash TEXT,code_hash TEXT); INSERT INTO credentials VALUES(1,'existing-owner','node-hash','node-code'); CREATE TABLE reports(year INTEGER, month INTEGER, rows TEXT NOT NULL,PRIMARY KEY(year,month)); INSERT INTO reports VALUES(2026,9,'[]');")
            connection.commit()
            connection.close()
            source = "require " + repr(str(public / 'bootstrap.php')) + "; $c=credentials(); if($c['login']!=='existing-owner'||$c['password_hash']!==''||$c['default_password']!==0||$db->query('SELECT COUNT(*) FROM reports')->fetchColumn()!=1)exit(1);"
            command = shlex.split(os.getenv('PHP_BIN','php')) + ['-r',source]
            subprocess.run(command,env=dict(os.environ,DATA_DIR=str(database)),check=True,capture_output=True)

    def test_login_reports_and_recovery(self):
        with tempfile.TemporaryDirectory(prefix='seller-php-') as directory:
            root = Path(directory)
            public = root / 'seller' / 'public'
            shutil.copytree(Path(__file__).resolve().parents[1] / 'public', public)
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            environment = dict(os.environ, DATA_DIR=str(root / 'database'))
            for name in ('ADMIN_LOGIN', 'ADMIN_PASSWORD', 'CLIENT_CODE'):
                environment.pop(name, None)
            command = shlex.split(os.getenv('PHP_BIN', 'php')) + ['-S', f'127.0.0.1:{port}', '-t', str(root)]
            with open(root / 'php.log', 'w') as log:
                process = subprocess.Popen(command, env=environment, stdout=log, stderr=log)
                try:
                    base = f'http://127.0.0.1:{port}/seller/public/'
                    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
                    def request(path, method='GET', body=None, token=None):
                        headers = {'Content-Type': 'application/json'}
                        if token:
                            headers['X-CSRF-Token'] = token
                        req = urllib.request.Request(base+path, data=json.dumps(body).encode() if body is not None else None, headers=headers, method=method)
                        try:
                            response = opener.open(req, timeout=5)
                        except urllib.error.HTTPError as error:
                            response = error
                        return response.status, response.read().decode()
                    def api(action, method='GET', body=None, token=None):
                        status, text = request('api.php?action='+action, method, body, token)
                        return status, json.loads(text)
                    for _ in range(100):
                        try:
                            status, payload = api('csrf')
                            break
                        except urllib.error.URLError:
                            if process.poll() is not None:
                                self.fail((root / 'php.log').read_text())
                            time.sleep(.05)
                    self.assertEqual(status, 200)
                    token = payload['token']
                    self.assertEqual(api('login', 'POST', {'role':'admin','login':'admin','password':'Admin123456!'})[0], 403)
                    self.assertEqual(api('login', 'POST', {'role':'admin','login':'admin','password':'Admin123456!'}, token)[0], 200)
                    self.assertEqual(api('years')[0], 403)
                    token = api('csrf')[1]['token']
                    self.assertEqual(api('access', 'PUT', {'currentPassword':'Admin123456!','newPassword':'new-test-password','code':'test-client-code'}, token)[0], 200)
                    rows = [{'type':'income','name':'Продажи','amount':123456}]
                    self.assertEqual(api('report', 'PUT', {'year':2026,'month':9,'rows':rows}, token)[0], 200)
                    self.assertEqual(api('report&year=2026&month=9')[1]['rows'], rows)
                    self.assertEqual(api('report&year=2026&month=10')[1]['rows'], [])
                    self.assertIn('Восстановление выключено', request('reset-password.php')[1])
                    flag = root / 'seller' / 'storage' / 'reset.allow'
                    flag.touch()
                    html = request('reset-password.php')[1]
                    csrf = re.search(r'name="csrf" value="([a-f0-9]+)"', html).group(1)
                    data = urllib.parse.urlencode({'csrf':csrf,'login':'admin','password':'reset-test-password','confirm':'reset-test-password'}).encode()
                    response = opener.open(urllib.request.Request(base+'reset-password.php', data=data))
                    self.assertIn('Пароль изменён', response.read().decode())
                    self.assertFalse(flag.exists())
                    self.assertEqual(api('session')[0], 401)
                    token = api('csrf')[1]['token']
                    self.assertEqual(api('login','POST',{'role':'admin','login':'admin','password':'new-test-password'},token)[0],401)
                    self.assertEqual(api('login','POST',{'role':'admin','login':'admin','password':'reset-test-password'},token)[0],200)
                    token = api('csrf')[1]['token']
                    self.assertEqual(api('logout','POST',{},token)[0],200)
                    token = api('csrf')[1]['token']
                    self.assertEqual(api('login','POST',{'code':'test-client-code'},token)[0],200)
                    self.assertEqual(api('access')[0],403)
                    token = api('csrf')[1]['token']
                    self.assertEqual(api('report','PUT',{'year':2026,'month':9,'rows':[]},token)[0],403)
                    self.assertEqual(api('report&year=2026&month=9')[1]['rows'],rows)
                finally:
                    process.terminate()
                    process.wait(timeout=10)

if __name__ == '__main__':
    unittest.main()
