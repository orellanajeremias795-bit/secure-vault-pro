<?php
declare(strict_types=1);

require __DIR__ . '/config.php';

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_name('svp_session');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => false,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();
}

function ensureDirs(): void {
    foreach ([STORAGE_DIR, UPLOAD_DIR, LOG_DIR] as $dir) {
        if (!is_dir($dir)) {
            @mkdir($dir, 0750, true);
        }
    }
}

function db(): PDO {
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }
    $pdo = new PDO(DB_DSN, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    return $pdo;
}

function redisCmd(array $parts): ?string {
    $sock = @fsockopen(REDIS_HOST, REDIS_PORT, $errno, $errstr, 1.5);
    if (!$sock) {
        return null;
    }

    $cmd = '*' . count($parts) . "\r\n";
    foreach ($parts as $p) {
        $p = (string)$p;
        $cmd .= '$' . strlen($p) . "\r\n" . $p . "\r\n";
    }

    fwrite($sock, $cmd);
    $first = fgets($sock, 8192);
    if ($first === false) {
        fclose($sock);
        return null;
    }

    $prefix = $first[0] ?? '';
    if ($prefix === '$') {
        $len = (int)trim(substr($first, 1));
        if ($len < 0) {
            fclose($sock);
            return null;
        }
        $data = '';
        while (strlen($data) < $len) {
            $chunk = fread($sock, $len - strlen($data));
            if ($chunk === false || $chunk === '') {
                break;
            }
            $data .= $chunk;
        }
        fread($sock, 2);
        fclose($sock);
        return $data;
    }

    fclose($sock);
    return trim($first);
}

function redisIncrWithExpiry(string $key, int $ttl): int {
    $resp = redisCmd(['INCR', $key]);
    if ($resp === null) {
        return 1;
    }
    $n = (int)ltrim($resp, ':');
    if ($n === 1) {
        redisCmd(['EXPIRE', $key, (string)$ttl]);
    }
    return $n;
}

function csrfToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(16));
    }
    return $_SESSION['csrf_token'];
}

function checkCsrf(string $token): bool {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

function e(string $v): string {
    return htmlspecialchars($v, ENT_QUOTES, 'UTF-8');
}

function bytesHuman(int $bytes): string {
    $units = ['B', 'KB', 'MB', 'GB'];
    $i = 0;
    $n = (float)$bytes;
    while ($n >= 1024 && $i < count($units) - 1) {
        $n /= 1024;
        $i++;
    }
    return number_format($n, 2) . ' ' . $units[$i];
}

function appLog(string $message): void {
    $line = date('c') . ' ' . $message . PHP_EOL;
    @file_put_contents(LOG_DIR . '/app.log', $line, FILE_APPEND);
}

function ensureSchema(): void {
    static $done = false;
    if ($done) return;

    $pdo = db();

    $pdo->exec("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user'");
    $pdo->exec("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS password_hash TEXT");
    $pdo->exec("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT true");
    $pdo->exec("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ");

    $pdo->exec("CREATE TABLE IF NOT EXISTS asset_audit_logs (
      id BIGSERIAL PRIMARY KEY,
      actor_user_id INT REFERENCES app_users(id),
      asset_id BIGINT,
      action TEXT NOT NULL,
      details JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )");

    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_asset_logs_created ON asset_audit_logs(created_at DESC)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_asset_logs_actor ON asset_audit_logs(actor_user_id, created_at DESC)");

    $pdo->exec("CREATE TABLE IF NOT EXISTS uploaded_assets (
      id BIGSERIAL PRIMARY KEY,
      uploader_id INT NOT NULL REFERENCES app_users(id),
      original_name TEXT NOT NULL,
      stored_name TEXT NOT NULL UNIQUE,
      file_path TEXT NOT NULL UNIQUE,
      mime_type TEXT NOT NULL,
      ext TEXT NOT NULL,
      category TEXT NOT NULL CHECK (category IN ('image','document')),
      size_bytes BIGINT NOT NULL CHECK (size_bytes > 0 AND size_bytes <= 10485760),
      sha256 CHAR(64) NOT NULL,
      policy_ack BOOLEAN NOT NULL DEFAULT false,
      is_active BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )");

    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_uploaded_assets_created_at ON uploaded_assets(created_at DESC)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_uploaded_assets_uploader_created ON uploaded_assets(uploader_id, created_at DESC)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_uploaded_assets_mime_created ON uploaded_assets(mime_type, created_at DESC)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_uploaded_assets_lower_name ON uploaded_assets((lower(original_name)))");

    // seed default admin password if missing
    $adminHash = password_hash('Admin@12345', PASSWORD_DEFAULT);
    $stmt = $pdo->prepare("UPDATE app_users
      SET role='admin', password_hash=COALESCE(password_hash, :h), is_active=true
      WHERE email='aryan@example.com'");
    $stmt->execute([':h' => $adminHash]);

    // seed missing hashes for existing users for demo login
    $users = $pdo->query("SELECT id, email FROM app_users WHERE password_hash IS NULL")->fetchAll();
    foreach ($users as $u) {
      $seed = 'User@12345';
      $h = password_hash($seed, PASSWORD_DEFAULT);
      $up = $pdo->prepare("UPDATE app_users SET password_hash=:h WHERE id=:id");
      $up->execute([':h' => $h, ':id' => (int)$u['id']]);
    }

    $done = true;
}

function currentUser(): ?array {
    if (empty($_SESSION['uid'])) return null;
    $stmt = db()->prepare("SELECT id, name, email, role, is_active, last_login_at FROM app_users WHERE id=:id");
    $stmt->execute([':id' => (int)$_SESSION['uid']]);
    $u = $stmt->fetch();
    if (!$u || !(bool)$u['is_active']) {
        return null;
    }
    return $u;
}

function requireLogin(): array {
    $u = currentUser();
    if (!$u) {
        header('Location: login.php');
        exit;
    }
    return $u;
}

function isAdmin(array $u): bool {
    return ($u['role'] ?? 'user') === 'admin';
}

function auditLog(int $actorId, ?int $assetId, string $action, array $details = []): void {
    $stmt = db()->prepare("INSERT INTO asset_audit_logs(actor_user_id, asset_id, action, details) VALUES(:a,:asset,:action,:d)");
    $stmt->execute([
        ':a' => $actorId,
        ':asset' => $assetId,
        ':action' => $action,
        ':d' => json_encode($details),
    ]);
}

ensureDirs();
ensureSchema();
