<?php
declare(strict_types=1);
require __DIR__ . '/../app/bootstrap.php';

if (currentUser()) {
    header('Location: index.php');
    exit;
}

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $limit = redisIncrWithExpiry('svp:login:rate:' . $ip, 60);
    if ($limit > LOGIN_RATE_LIMIT_PER_MIN) {
        $error = 'Too many login attempts. Please wait 1 minute.';
    } else {
        $email = trim((string)($_POST['email'] ?? ''));
        $pass = (string)($_POST['password'] ?? '');
        $csrf = (string)($_POST['csrf_token'] ?? '');

        if (!checkCsrf($csrf)) {
            $error = 'Security token mismatch.';
        } else {
            $stmt = db()->prepare("SELECT id, name, email, role, password_hash, is_active FROM app_users WHERE lower(email)=lower(:e) LIMIT 1");
            $stmt->execute([':e' => $email]);
            $u = $stmt->fetch();

            if ($u && (bool)$u['is_active'] && !empty($u['password_hash']) && password_verify($pass, (string)$u['password_hash'])) {
                $_SESSION['uid'] = (int)$u['id'];
                $_SESSION['login_at'] = time();
                db()->prepare("UPDATE app_users SET last_login_at=NOW() WHERE id=:id")->execute([':id' => (int)$u['id']]);
                header('Location: index.php');
                exit;
            }
            $error = 'Invalid credentials or inactive account.';
        }
    }
}

$token = csrfToken();
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title><?= e(APP_NAME) ?> | Login</title>
  <link rel="stylesheet" href="assets/app.css" />
</head>
<body class="auth-body">
  <div class="auth-card">
    <h1><?= e(APP_NAME) ?></h1>
    <p class="muted">Production-style secure upload app using PostgreSQL + Redis + PHP (XAMPP).</p>
    <?php if ($error !== ''): ?><div class="flash error"><?= e($error) ?></div><?php endif; ?>

    <form method="post">
      <input type="hidden" name="csrf_token" value="<?= e($token) ?>">
      <label>Email</label>
      <input type="email" name="email" required placeholder="aryan@example.com" />
      <label>Password</label>
      <input type="password" name="password" required placeholder="••••••••" />
      <button type="submit" class="btn btn-primary">Login</button>
    </form>

    <div class="tip">
      <strong>Demo Admin:</strong> aryan@example.com / Admin@12345<br>
      <strong>Demo User:</strong> any existing user email / User@12345
    </div>
  </div>
</body>
</html>
