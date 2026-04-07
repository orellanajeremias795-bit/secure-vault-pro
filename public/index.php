<?php
declare(strict_types=1);
require __DIR__ . '/../app/bootstrap.php';

$user = requireLogin();
$isAdminUser = isAdmin($user);
$messages = [];
$errors = [];

function redirectSelf(array $query = []): void {
    $qs = http_build_query($query);
    header('Location: index.php' . ($qs ? ('?' . $qs) : ''));
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrf = (string)($_POST['csrf_token'] ?? '');
    if (!checkCsrf($csrf)) {
        $errors[] = 'Invalid CSRF token.';
    } else {
        $action = (string)($_POST['action'] ?? '');

        if ($action === 'upload') {
            $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            $n = redisIncrWithExpiry('svp:upload:rate:' . $ip, 60);
            if ($n > UPLOAD_RATE_LIMIT_PER_MIN) {
                $errors[] = 'Too many uploads from your IP in 1 minute.';
            }

            $uploaderId = (int)($_POST['uploader_id'] ?? $user['id']);
            if (!$isAdminUser) {
                $uploaderId = (int)$user['id'];
            }

            $policyAck = isset($_POST['policy_ack']) && $_POST['policy_ack'] === 'on';
            if (!$policyAck) {
                $errors[] = 'Policy acknowledgment required.';
            }

            if (!isset($_FILES['asset']) || !is_array($_FILES['asset'])) {
                $errors[] = 'Please choose a file.';
            }

            if (empty($errors) && isset($_FILES['asset'])) {
                $f = $_FILES['asset'];
                if (($f['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
                    $errors[] = 'Upload failed with code: ' . (int)$f['error'];
                } elseif ((int)($f['size'] ?? 0) <= 0 || (int)$f['size'] > MAX_UPLOAD_BYTES) {
                    $errors[] = 'File must be >0 and <=10MB.';
                } else {
                    $originalName = (string)$f['name'];
                    $tmp = (string)$f['tmp_name'];
                    $ext = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));

                    if (!isset(ALLOWED_EXT_MIME[$ext])) {
                        $errors[] = 'Extension not allowed.';
                    } else {
                        $finfo = new finfo(FILEINFO_MIME_TYPE);
                        $mime = (string)$finfo->file($tmp);
                        if (!in_array($mime, ALLOWED_EXT_MIME[$ext], true)) {
                            $errors[] = 'MIME mismatch. Blocked.';
                        }

                        if (empty($errors)) {
                            $category = in_array($ext, ['jpg','jpeg','png','gif','webp'], true) ? 'image' : 'document';
                            $stored = bin2hex(random_bytes(16)) . '.' . $ext;
                            $dest = rtrim(UPLOAD_DIR, '/') . '/' . $stored;

                            if (!is_uploaded_file($tmp) || !move_uploaded_file($tmp, $dest)) {
                                $errors[] = 'Failed to secure-store upload.';
                            } else {
                                @chmod($dest, 0640);
                                $sha256 = hash_file('sha256', $dest);

                                $stmt = db()->prepare("INSERT INTO uploaded_assets (
                                  uploader_id, original_name, stored_name, file_path, mime_type, ext, category, size_bytes, sha256, policy_ack
                                ) VALUES (
                                  :uid,:on,:sn,:fp,:mime,:ext,:cat,:sz,:sha,:ack
                                )");
                                $stmt->execute([
                                    ':uid' => $uploaderId,
                                    ':on' => $originalName,
                                    ':sn' => $stored,
                                    ':fp' => $dest,
                                    ':mime' => $mime,
                                    ':ext' => $ext,
                                    ':cat' => $category,
                                    ':sz' => (int)$f['size'],
                                    ':sha' => $sha256,
                                    ':ack' => $policyAck,
                                ]);

                                $assetId = (int)db()->lastInsertId();
                                auditLog((int)$user['id'], $assetId, 'upload', [
                                    'name' => $originalName,
                                    'size' => (int)$f['size'],
                                    'mime' => $mime,
                                ]);
                                redisCmd(['INCR', 'svp:assets:version']);
                                $messages[] = 'Upload successful.';
                            }
                        }
                    }
                }
            }
        }

        if ($action === 'toggle_asset' && $isAdminUser) {
            $assetId = (int)($_POST['asset_id'] ?? 0);
            $enable = (int)($_POST['enable'] ?? 0) === 1;
            if ($assetId > 0) {
                db()->prepare("UPDATE uploaded_assets SET is_active=:a WHERE id=:id")
                   ->execute([':a' => $enable, ':id' => $assetId]);
                auditLog((int)$user['id'], $assetId, $enable ? 'asset_restore' : 'asset_disable');
                redisCmd(['INCR', 'svp:assets:version']);
                $messages[] = $enable ? 'Asset restored.' : 'Asset disabled.';
            }
        }

        if ($action === 'toggle_user' && $isAdminUser) {
            $targetId = (int)($_POST['target_user_id'] ?? 0);
            $enable = (int)($_POST['enable'] ?? 0) === 1;
            if ($targetId > 0 && $targetId !== (int)$user['id']) {
                db()->prepare("UPDATE app_users SET is_active=:a WHERE id=:id")
                  ->execute([':a' => $enable, ':id' => $targetId]);
                auditLog((int)$user['id'], null, $enable ? 'user_enable' : 'user_disable', ['target_user_id' => $targetId]);
                $messages[] = $enable ? 'User enabled.' : 'User disabled.';
            }
        }

        if ($action === 'create_user' && $isAdminUser) {
            $name = trim((string)($_POST['name'] ?? ''));
            $email = trim((string)($_POST['email'] ?? ''));
            $role = (string)($_POST['role'] ?? 'user');
            $password = (string)($_POST['password'] ?? '');

            if ($name === '' || $email === '' || $password === '') {
                $errors[] = 'Name, email and password are required.';
            } elseif (!in_array($role, ['admin','user'], true)) {
                $errors[] = 'Invalid role.';
            } elseif (strlen($password) < 8) {
                $errors[] = 'Password must be at least 8 chars.';
            } else {
                try {
                    $stmt = db()->prepare("INSERT INTO app_users(name,email,role,password_hash,is_active) VALUES(:n,:e,:r,:p,true)");
                    $stmt->execute([
                        ':n' => $name,
                        ':e' => $email,
                        ':r' => $role,
                        ':p' => password_hash($password, PASSWORD_DEFAULT),
                    ]);
                    $newId = (int)db()->lastInsertId();
                    auditLog((int)$user['id'], null, 'user_create', ['target_user_id' => $newId, 'email' => $email, 'role' => $role]);
                    $messages[] = 'User created.';
                } catch (Throwable $e) {
                    $errors[] = 'Create user failed: ' . $e->getMessage();
                }
            }
        }
    }
}

$q = trim((string)($_GET['q'] ?? ''));
$onlyMine = isset($_GET['mine']) && $_GET['mine'] === '1';

$version = redisCmd(['GET', 'svp:assets:version']);
if ($version === null || $version === '') {
    $version = '1';
    redisCmd(['SET', 'svp:assets:version', '1']);
}

$listCacheKey = 'svp:list:v' . $version . ':u' . $user['id'] . ':a' . ($isAdminUser ? '1':'0') . ':m' . ($onlyMine ? '1':'0') . ':q' . sha1($q);
$cacheState = 'MISS';
$listData = null;

$cached = redisCmd(['GET', $listCacheKey]);
if ($cached !== null && $cached !== '') {
    $decoded = json_decode($cached, true);
    if (is_array($decoded)) {
        $listData = $decoded;
        $cacheState = 'HIT';
    }
}

if (!is_array($listData)) {
$where = ["a.is_active=true"];
$params = [':q' => $q];
$where[] = "(:q = '' OR lower(a.original_name) LIKE '%'||lower(:q)||'%' OR lower(u.name) LIKE '%'||lower(:q)||'%' OR lower(a.category) LIKE '%'||lower(:q)||'%')";

    if (!$isAdminUser || $onlyMine) {
        $where[] = "a.uploader_id=:uid";
        $params[':uid'] = (int)$user['id'];
    }

    $whereSql = implode(' AND ', $where);

    $sql = "WITH filtered AS (
      SELECT a.id,a.original_name,a.mime_type,a.category,a.size_bytes,a.created_at,a.uploader_id,a.is_active,
             u.name AS uploader_name,u.email AS uploader_email,
             COUNT(*) OVER(PARTITION BY a.category) AS category_total,
             ROW_NUMBER() OVER(PARTITION BY a.uploader_id ORDER BY a.created_at DESC) AS uploader_recent_rank
      FROM uploaded_assets a
      JOIN app_users u ON u.id=a.uploader_id
      WHERE $whereSql
    )
    SELECT * FROM filtered ORDER BY created_at DESC LIMIT 200";

    $stmt = db()->prepare($sql);
    $stmt->execute($params);
    $rows = $stmt->fetchAll();

    $sumSql = "SELECT COUNT(*) AS total_files,
                      COALESCE(SUM(size_bytes),0) AS total_bytes,
                      COUNT(*) FILTER (WHERE category='image') AS total_images,
                      COUNT(*) FILTER (WHERE category='document') AS total_documents,
                      COUNT(DISTINCT uploader_id) AS contributors
                FROM uploaded_assets a
                JOIN app_users u ON u.id=a.uploader_id
                WHERE $whereSql";
    $sumStmt = db()->prepare($sumSql);
    $sumStmt->execute($params);
    $summary = $sumStmt->fetch() ?: [
        'total_files' => 0,
        'total_bytes' => 0,
        'total_images' => 0,
        'total_documents' => 0,
        'contributors' => 0,
    ];

    $listData = ['rows' => $rows, 'summary' => $summary];
    $json = json_encode($listData);
    if ($json !== false) {
        redisCmd(['SETEX', $listCacheKey, (string)LIST_CACHE_TTL, $json]);
    }
}

$dashKey = 'svp:dash:v' . $version . ':admin:' . ($isAdminUser ? '1' : '0');
$dash = null;
$dashCached = redisCmd(['GET', $dashKey]);
if ($dashCached !== null && $dashCached !== '') {
    $dc = json_decode($dashCached, true);
    if (is_array($dc)) {
        $dash = $dc;
    }
}
if (!is_array($dash)) {
    $dashSql = "SELECT
      date_trunc('day', created_at)::date AS day,
      COUNT(*) AS uploads,
      COALESCE(SUM(size_bytes),0) AS bytes
      FROM uploaded_assets
      WHERE created_at >= NOW() - INTERVAL '7 days'
      GROUP BY 1
      ORDER BY 1";
    $dash = db()->query($dashSql)->fetchAll();
    $j = json_encode($dash);
    if ($j !== false) {
        redisCmd(['SETEX', $dashKey, (string)DASH_CACHE_TTL, $j]);
    }
}

$users = [];
$audits = [];
if ($isAdminUser) {
    $users = db()->query("SELECT id,name,email,role,is_active,last_login_at,created_at FROM app_users ORDER BY id DESC")->fetchAll();
    $audits = db()->query("SELECT l.id,l.action,l.created_at,u.name AS actor_name,l.asset_id,l.details
                          FROM asset_audit_logs l
                          LEFT JOIN app_users u ON u.id=l.actor_user_id
                          ORDER BY l.created_at DESC LIMIT 30")->fetchAll();
}

$token = csrfToken();
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title><?= e(APP_NAME) ?> | Dashboard</title>
  <link rel="stylesheet" href="assets/app.css" />
</head>
<body>
  <div class="topbar">
    <div>
      <h1><?= e(APP_NAME) ?></h1>
      <div class="muted">Welcome, <?= e((string)$user['name']) ?> (<?= e((string)$user['role']) ?>)</div>
    </div>
    <div class="top-actions">
      <a href="index.php" class="btn">Dashboard</a>
      <?php if ($isAdminUser): ?><a href="#admin" class="btn">Admin Panel</a><?php endif; ?>
      <a href="logout.php" class="btn btn-danger">Logout</a>
    </div>
  </div>

  <?php foreach ($messages as $m): ?><div class="flash success"><?= e($m) ?></div><?php endforeach; ?>
  <?php foreach ($errors as $e): ?><div class="flash error"><?= e($e) ?></div><?php endforeach; ?>

  <div class="grid two">
    <div class="card">
      <h3>Upload Center</h3>
      <form method="post" enctype="multipart/form-data">
        <input type="hidden" name="csrf_token" value="<?= e($token) ?>">
        <input type="hidden" name="action" value="upload">

        <label>Uploader</label>
        <select name="uploader_id" <?= $isAdminUser ? '' : 'disabled' ?>>
          <?php
            $opts = db()->query("SELECT id,name,email FROM app_users WHERE is_active=true ORDER BY id")->fetchAll();
            foreach ($opts as $ou):
          ?>
            <option value="<?= (int)$ou['id'] ?>" <?= ((int)$ou['id'] === (int)$user['id']) ? 'selected' : '' ?>>
              <?= e($ou['name']) ?> (<?= e($ou['email']) ?>)
            </option>
          <?php endforeach; ?>
        </select>

        <label>Select file</label>
        <input type="file" name="asset" required>
        <label class="check"><input type="checkbox" name="policy_ack" required> I agree to policy: safe/legal files only.</label>
        <button class="btn btn-primary" type="submit">Upload Securely</button>
        <p class="muted">Allowed: jpg, jpeg, png, gif, webp, pdf, txt, doc, docx. Max 10MB.</p>
      </form>
    </div>

    <div class="card">
      <h3>Smart Search + Stats</h3>
      <form method="get" class="inline-form">
        <input type="text" name="q" placeholder="name/uploader/category" value="<?= e($q) ?>">
        <label class="check"><input type="checkbox" name="mine" value="1" <?= $onlyMine ? 'checked' : '' ?>> Only my uploads</label>
        <button class="btn" type="submit">Apply</button>
      </form>
      <div class="stat-grid">
        <div><small>Cache</small><strong class="<?= $cacheState === 'HIT' ? 'ok' : 'warn' ?>"><?= e($cacheState) ?></strong></div>
        <div><small>Total Files</small><strong><?= (int)$listData['summary']['total_files'] ?></strong></div>
        <div><small>Total Images</small><strong><?= (int)$listData['summary']['total_images'] ?></strong></div>
        <div><small>Total Docs</small><strong><?= (int)$listData['summary']['total_documents'] ?></strong></div>
        <div><small>Storage</small><strong><?= e(bytesHuman((int)$listData['summary']['total_bytes'])) ?></strong></div>
        <div><small>Contributors</small><strong><?= (int)$listData['summary']['contributors'] ?></strong></div>
      </div>
      <div class="muted">CTE + window functions + indexed filters + Redis cache.</div>
    </div>
  </div>

  <div class="card" style="margin-top:16px;">
    <h3>Activity (Last 7 Days)</h3>
    <div class="bars">
      <?php foreach ($dash as $d):
        $height = max(8, (int)$d['uploads'] * 16);
      ?>
        <div class="bar-item" title="<?= e((string)$d['day']) ?>: <?= (int)$d['uploads'] ?> uploads">
          <div class="bar" style="height:<?= $height ?>px;"></div>
          <span><?= e(substr((string)$d['day'], 5)) ?></span>
        </div>
      <?php endforeach; ?>
    </div>
  </div>

  <div class="card" style="margin-top:16px;">
    <h3>Assets</h3>
    <table>
      <thead><tr><th>ID</th><th>Name</th><th>Type</th><th>Category</th><th>Size</th><th>Uploader</th><th>Rank</th><th>Created</th><th>Actions</th></tr></thead>
      <tbody>
      <?php foreach ($listData['rows'] as $r): ?>
        <tr>
          <td><?= (int)$r['id'] ?></td>
          <td><?= e($r['original_name']) ?></td>
          <td><?= e($r['mime_type']) ?></td>
          <td><?= e($r['category']) ?> (<?= (int)$r['category_total'] ?>)</td>
          <td><?= e(bytesHuman((int)$r['size_bytes'])) ?></td>
          <td><?= e($r['uploader_name']) ?></td>
          <td>#<?= (int)$r['uploader_recent_rank'] ?></td>
          <td><?= e((string)$r['created_at']) ?></td>
          <td>
            <a class="btn btn-mini" href="download.php?id=<?= (int)$r['id'] ?>">Download</a>
            <?php if ($isAdminUser): ?>
              <form method="post" style="display:inline;">
                <input type="hidden" name="csrf_token" value="<?= e($token) ?>">
                <input type="hidden" name="action" value="toggle_asset">
                <input type="hidden" name="asset_id" value="<?= (int)$r['id'] ?>">
                <input type="hidden" name="enable" value="0">
                <button class="btn btn-mini btn-danger" type="submit">Disable</button>
              </form>
            <?php endif; ?>
          </td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </div>

  <?php if ($isAdminUser): ?>
  <div id="admin" class="grid two" style="margin-top:16px;">
    <div class="card">
      <h3>Admin: Create User</h3>
      <form method="post">
        <input type="hidden" name="csrf_token" value="<?= e($token) ?>">
        <input type="hidden" name="action" value="create_user">
        <input type="text" name="name" placeholder="Name" required>
        <input type="email" name="email" placeholder="Email" required>
        <select name="role"><option value="user">user</option><option value="admin">admin</option></select>
        <input type="password" name="password" placeholder="Initial password" required>
        <button class="btn btn-primary" type="submit">Create User</button>
      </form>

      <h3 style="margin-top:16px;">Admin: Users</h3>
      <table>
        <thead><tr><th>ID</th><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Last Login</th><th>Action</th></tr></thead>
        <tbody>
        <?php foreach ($users as $u): ?>
          <tr>
            <td><?= (int)$u['id'] ?></td>
            <td><?= e($u['name']) ?></td>
            <td><?= e($u['email']) ?></td>
            <td><?= e($u['role']) ?></td>
            <td><?= (bool)$u['is_active'] ? 'active' : 'disabled' ?></td>
            <td><?= e((string)($u['last_login_at'] ?? '-')) ?></td>
            <td>
              <?php if ((int)$u['id'] !== (int)$user['id']): ?>
              <form method="post" style="display:inline;">
                <input type="hidden" name="csrf_token" value="<?= e($token) ?>">
                <input type="hidden" name="action" value="toggle_user">
                <input type="hidden" name="target_user_id" value="<?= (int)$u['id'] ?>">
                <input type="hidden" name="enable" value="<?= (bool)$u['is_active'] ? 0 : 1 ?>">
                <button class="btn btn-mini <?= (bool)$u['is_active'] ? 'btn-danger' : '' ?>" type="submit"><?= (bool)$u['is_active'] ? 'Disable' : 'Enable' ?></button>
              </form>
              <?php endif; ?>
            </td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </div>

    <div class="card">
      <h3>Admin: Audit Logs</h3>
      <table>
        <thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Asset</th><th>Details</th></tr></thead>
        <tbody>
        <?php foreach ($audits as $l): ?>
          <tr>
            <td><?= e((string)$l['created_at']) ?></td>
            <td><?= e((string)($l['actor_name'] ?? 'system')) ?></td>
            <td><?= e((string)$l['action']) ?></td>
            <td><?= e((string)($l['asset_id'] ?? '-')) ?></td>
            <td><code><?= e((string)$l['details']) ?></code></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </div>
  </div>
  <?php endif; ?>

</body>
</html>
