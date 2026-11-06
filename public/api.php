<?php
declare(strict_types=1);
try {
require __DIR__.'/bootstrap.php';
$action=$_GET['action']??'';$method=$_SERVER['REQUEST_METHOD'];
if ($method==='GET' && $action==='csrf') json_response(200,['token'=>csrf()]);
$b=[];
if ($method!=='GET') {
 check_csrf($_SERVER['HTTP_X_CSRF_TOKEN']??'');
 if ((int)($_SERVER['CONTENT_LENGTH']??0)>1048576) json_response(413,['error'=>'Слишком большой запрос']);
 $raw=file_get_contents('php://input',false,null,0,1048577);if(strlen($raw)>1048576)json_response(413,['error'=>'Слишком большой запрос']);
 $b=json_decode($raw===''?'{}':$raw,true,512,JSON_THROW_ON_ERROR);if(!is_array($b))json_response(400,['error'=>'Неверный запрос']);
}
if ($action==='login' && $method==='POST') {
 check_limit();$c=credentials();$admin=($b['role']??'')==='admin';
 $secret=$admin?($b['password']??''):($b['code']??'');$hash=$admin?$c['password_hash']:$c['code_hash'];
 if(!is_string($secret)||strlen($secret)>1024||!$hash||($admin&&($b['login']??'')!==$c['login'])||!password_verify($secret,$hash)){failed_attempt();json_response(401,['error'=>'Неверные данные для входа. Если забыли пароль, используйте восстановление.']);}
 session_regenerate_id(true);$_SESSION=['role'=>$admin?'admin':'client','expires'=>time()+28800,'version'=>$c['version'],'client_version'=>$c['client_version']];clear_attempts();json_response(200,['role'=>$_SESSION['role']]);
}
$role=current_role();if(!$role)json_response(401,['error'=>'Необходим вход']);
if($action==='session'&&$method==='GET')json_response(200,['role'=>$role]);
if($action==='logout'&&$method==='POST'){$_SESSION=[];session_regenerate_id(true);json_response(200,[]);}
if($action==='access'){
 if($role!=='admin')json_response(403,['error'=>'Только для администратора']);$c=credentials();
 if($method==='GET')json_response(200,['login'=>$c['login'],'passwordChangeRequired'=>(bool)$c['default_password'],'clientCodeConfigured'=>(bool)$c['code_hash']]);
 if($method==='PUT'){
 check_limit();if(!is_string($b['currentPassword']??null)||!password_verify($b['currentPassword'],$c['password_hash'])){failed_attempt();json_response(403,['error'=>'Неверный текущий пароль']);}
 $password=$b['newPassword']??null;$code=$b['code']??null;
 if(($password!==null&&(!is_string($password)||strlen($password)<12||strlen($password)>256))||($code!==null&&(!is_string($code)||strlen($code)<8||strlen($code)>256))||(!$password&&!$code))json_response(400,['error'=>'Пароль: 12–256 символов. Код: 8–256 символов.']);
 if($c['default_password']&&!$password)json_response(400,['error'=>'Замените стандартный пароль']);
 if($password&&password_verify($password,$c['password_hash']))json_response(400,['error'=>'Новый пароль должен отличаться от текущего']);
 $q=$db->prepare('UPDATE php_credentials SET password_hash=?,code_hash=?,default_password=?,version=version+?,client_version=client_version+? WHERE id=1');$q->execute([$password?password_hash($password,PASSWORD_DEFAULT):$c['password_hash'],$code?password_hash($code,PASSWORD_DEFAULT):$c['code_hash'],$password?0:$c['default_password'],$password?1:0,$code?1:0]);$updated=credentials();$_SESSION['version']=$updated['version'];$_SESSION['client_version']=$updated['client_version'];clear_attempts();json_response(200,['saved'=>true]);
 }
}
if($role==='admin'&&credentials()['default_password'])json_response(403,['error'=>'Сначала замените стандартный пароль']);
if($action==='years'&&$method==='GET')json_response(200,array_column($db->query('SELECT year FROM years ORDER BY year DESC')->fetchAll(),'year'));
if($method!=='GET'&&$role!=='admin')json_response(403,['error'=>'Только для администратора']);
if($action==='years'&&$method==='POST'){if(!valid_period($b['year']??null,1))json_response(400,['error'=>'Год: 2000–2100']);$q=$db->prepare('INSERT OR IGNORE INTO years VALUES(?)');$q->execute([$b['year']]);json_response(200,['year'=>$b['year']]);}
if($action==='report'&&$method==='GET'){$year=(int)($_GET['year']??0);$month=(int)($_GET['month']??0);if(!valid_period($year,$month))json_response(400,['error'=>'Неверный период']);$q=$db->prepare('SELECT rows FROM reports WHERE year=? AND month=?');$q->execute([$year,$month]);$r=$q->fetch();json_response(200,['rows'=>$r?json_decode($r['rows'],true,512,JSON_THROW_ON_ERROR):[]]);}
if($action==='report'&&$method==='PUT'){
 $rows=$b['rows']??null;if(!valid_period($b['year']??null,$b['month']??null)||!is_array($rows)||!array_is_list($rows)||count($rows)>2000)json_response(400,['error'=>'Неверный отчёт']);$clean=[];
 foreach($rows as $r){if(!is_array($r)||!in_array($r['type']??'', ['income','expense'],true)||!is_string($r['name']??null)||!trim($r['name'])||strlen($r['name'])>2000||!is_int($r['amount']??null)||$r['amount']<0||$r['amount']>1000000000000)json_response(400,['error'=>'Проверьте названия и положительные суммы']);$clean[]=['type'=>$r['type'],'name'=>trim($r['name']),'amount'=>$r['amount']];}
 $db->beginTransaction();try{$q=$db->prepare('INSERT OR IGNORE INTO years VALUES(?)');$q->execute([$b['year']]);$q=$db->prepare('INSERT INTO reports VALUES(?,?,?) ON CONFLICT(year,month) DO UPDATE SET rows=excluded.rows');$q->execute([$b['year'],$b['month'],json_encode($clean,JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR)]);$db->commit();}catch(Throwable $e){$db->rollBack();throw $e;}json_response(200,['saved'=>true]);
}
json_response(404,['error'=>'Не найдено']);
}catch(Throwable $e){error_log('seller: '.$e->getMessage());http_response_code(503);header('Content-Type: application/json; charset=utf-8');echo json_encode(['error'=>'Ошибка сервера. Проверьте PHP 8.1+, расширения pdo_sqlite и права записи в data и storage. Подробности в журнале Plesk.'],JSON_UNESCAPED_UNICODE);}
