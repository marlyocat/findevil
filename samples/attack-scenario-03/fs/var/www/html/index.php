<?php
require_once __DIR__ . '/lib/bootstrap.php';

$user = current_user();

?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>webserver-prod-03 CMS</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <header>
    <img src="/logo.png" alt="Logo">
    <h1>Welcome<?php echo $user ? ", {$user['name']}" : ""; ?></h1>
  </header>

  <nav>
    <a href="/dashboard.php">Dashboard</a>
    <a href="/login.php">Login</a>
  </nav>

  <main>
    <p>A small PHP CMS. Serves the landing page for the marketing site.</p>
  </main>
</body>
</html>
