<?php
require_once __DIR__ . '/lib/bootstrap.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    $user = authenticate($username, $password);
    if ($user) {
        start_session_for($user);
        header('Location: /dashboard.php');
        exit;
    }
    $error = "Invalid credentials";
}
?>
<!DOCTYPE html>
<html lang="en">
<head><title>Login</title><link rel="stylesheet" href="/style.css"></head>
<body>
  <h1>Login</h1>
  <?php if (!empty($error)) echo "<p class='err'>{$error}</p>"; ?>
  <form method="post" action="/login.php">
    <label>Username <input name="username" required></label>
    <label>Password <input name="password" type="password" required></label>
    <button type="submit">Sign in</button>
  </form>
</body>
</html>
