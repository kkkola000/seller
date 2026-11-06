<?php
declare(strict_types=1);
$error='';$done=false;$allowed=false;
function e(string $s): string { return htmlspecialchars($s,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8'); }
try {
 require __DIR__.'/bootstrap.php';
 $flag=$storage.'/reset.allow';$allowed=is_file($flag);
 if($allowed&&$_SERVER['REQUEST_METHOD']==='POST'){
  if(!hash_equals(csrf(),(string)($_POST['csrf']??'')))throw new RuntimeException('Сессия формы истекла. Обновите страницу.');
  $password=$_POST['password']??'';$confirm=$_POST['confirm']??'';
  if(!is_string($password)||strlen($password)<12||strlen($password)>256)throw new RuntimeException('Пароль должен содержать от 12 до 256 символов.');
  if($password!==$confirm)throw new RuntimeException('Пароли не совпадают.');
  if(($_POST['login']??'')!==credentials()['login'])throw new RuntimeException('Неверный логин.');
  $hash=password_hash($password,PASSWORD_DEFAULT);
  $consumed=$storage.'/reset.used.'.bin2hex(random_bytes(12));
  if(!rename($flag,$consumed))throw new RuntimeException('Разрешение уже использовано.');
  try{$q=$db->prepare('UPDATE php_credentials SET password_hash=?,default_password=0,version=version+1 WHERE id=1');$q->execute([$hash]);}catch(Throwable $ex){rename($consumed,$flag);throw $ex;}
  unlink($consumed);$_SESSION=[];session_regenerate_id(true);$done=true;$allowed=false;
 }
}catch(Throwable $ex){error_log('seller reset: '.$ex->getMessage());$error=isset($db)?$ex->getMessage():'Не удалось открыть базу. Проверьте PHP pdo_sqlite и права записи в data/storage.';}
?>
<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex"><title>Восстановление доступа</title><link rel="stylesheet" href="./style.css"></head><body><main><section class="login"><h1>Восстановление доступа</h1>
<?php if($error): ?><p class="error" role="alert"><?=e($error)?></p><?php endif; ?>
<?php if($done): ?><p class="notice">Пароль изменён. Разрешение использовано, старые сеансы завершены.</p>
<?php elseif(!$allowed): ?><p>Восстановление выключено.</p><p>В файловом менеджере Plesk откройте папку <b>seller/storage</b> и создайте пустой файл <b>reset.allow</b>. Затем обновите эту страницу. После смены пароля файл удалится автоматически.</p>
<?php else: ?><form method="post"><input type="hidden" name="csrf" value="<?=e(csrf())?>"><label>Логин<input name="login" value="<?=e(credentials()['login'])?>" autocomplete="username" required></label><label>Новый пароль<input name="password" type="password" autocomplete="new-password" minlength="12" maxlength="256" required></label><label>Повторите пароль<input name="confirm" type="password" autocomplete="new-password" minlength="12" maxlength="256" required></label><button class="primary">Сохранить пароль</button></form><?php endif; ?>
<a href="./index.html">Войти в админку</a></section></main></body></html>
