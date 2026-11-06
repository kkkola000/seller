<?php
declare(strict_types=1);
ini_set('display_errors', '0');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: same-origin');
$storage = dirname(__DIR__) . '/storage';
$dir = getenv('DATA_DIR') ?: dirname(__DIR__) . '/data';
if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) throw new RuntimeException('Storage unavailable');
if (!is_dir($storage) && !mkdir($storage, 0700, true) && !is_dir($storage)) throw new RuntimeException('Storage unavailable');
session_name('seller_session');
session_set_cookie_params(['httponly'=>true, 'secure'=>(!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'), 'samesite'=>'Strict', 'path'=>'/']);
session_start();
$db = new PDO('sqlite:' . $dir . '/finance.sqlite', null, null, [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC]);
$db->exec('PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS reports(year INTEGER, month INTEGER, rows TEXT NOT NULL, PRIMARY KEY(year,month));
CREATE TABLE IF NOT EXISTS years(year INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS php_credentials(id INTEGER PRIMARY KEY CHECK(id=1), login TEXT NOT NULL, password_hash TEXT NOT NULL, code_hash TEXT NOT NULL, default_password INTEGER NOT NULL, version INTEGER NOT NULL DEFAULT 1, client_version INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS auth_attempts(ip TEXT PRIMARY KEY, count INTEGER NOT NULL, expires INTEGER NOT NULL);');
function credentials(): array { global $db; return $db->query('SELECT * FROM php_credentials WHERE id=1')->fetch(); }
if (!$db->query('SELECT id FROM php_credentials WHERE id=1')->fetch()) {
    $old = $db->query("SELECT name FROM sqlite_master WHERE type='table' AND name='credentials'")->fetch();
    $old = $old ? $db->query('SELECT login FROM credentials WHERE id=1')->fetch() : false;
    $legacy = getenv('ADMIN_LOGIN') && getenv('ADMIN_PASSWORD') && getenv('CLIENT_CODE');
    $login = $old['login'] ?? ($legacy ? getenv('ADMIN_LOGIN') : 'admin');
    // Never reset a previously configured Node.js account to a public default password.
    $password = $old ? '' : password_hash($legacy ? getenv('ADMIN_PASSWORD') : 'Admin123456!', PASSWORD_DEFAULT);
    $q=$db->prepare('INSERT OR IGNORE INTO php_credentials VALUES(1,?,?,?,?,1,1)');
    $q->execute([$login,$password,(!$old && $legacy) ? password_hash(getenv('CLIENT_CODE'), PASSWORD_DEFAULT) : '', (!$old && !$legacy) ? 1 : 0]);
}
function json_response(int $status, mixed $body): never { http_response_code($status); header('Content-Type: application/json; charset=utf-8'); echo json_encode($body, JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR); exit; }
function csrf(): string { return $_SESSION['csrf'] ??= bin2hex(random_bytes(32)); }
function check_csrf(string $token): void { if (!hash_equals(csrf(), $token)) json_response(403,['error'=>'Сессия формы истекла. Обновите страницу.']); }
function current_role(): ?string { $c=credentials(); if (($_SESSION['expires']??0)<time() || ($_SESSION['version']??0)!==$c['version']) return null; if (($_SESSION['role']??null)==='client' && ($_SESSION['client_version']??0)!==$c['client_version']) return null; return $_SESSION['role']??null; }
function check_limit(): void { global $db; $q=$db->prepare('SELECT * FROM auth_attempts WHERE ip=?'); $q->execute([$_SERVER['REMOTE_ADDR']??'unknown']); $r=$q->fetch(); if ($r && $r['expires']>time() && $r['count']>=10) json_response(429,['error'=>'Слишком много попыток. Повторите через 15 минут.']); }
function failed_attempt(): void { global $db; $q=$db->prepare('INSERT INTO auth_attempts VALUES(?,1,?) ON CONFLICT(ip) DO UPDATE SET count=CASE WHEN expires < ? THEN 1 ELSE count+1 END, expires=CASE WHEN expires < ? THEN excluded.expires ELSE expires END');$q->execute([$_SERVER['REMOTE_ADDR']??'unknown',time()+900,time(),time()]); }
function clear_attempts(): void { global $db; $q=$db->prepare('DELETE FROM auth_attempts WHERE ip=?');$q->execute([$_SERVER['REMOTE_ADDR']??'unknown']); }
function valid_period(mixed $y,mixed $m): bool { return is_int($y)&&$y>=2000&&$y<=2100&&is_int($m)&&$m>=1&&$m<=12; }
