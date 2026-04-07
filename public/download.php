<?php
declare(strict_types=1);
require __DIR__ . '/../app/bootstrap.php';
$user = requireLogin();

$id = (int)($_GET['id'] ?? 0);
if ($id <= 0) {
    http_response_code(400);
    exit('Invalid file id');
}

$sql = "SELECT a.* FROM uploaded_assets a WHERE a.id=:id";
$stmt = db()->prepare($sql);
$stmt->execute([':id' => $id]);
$row = $stmt->fetch();

if (!$row || !(bool)$row['is_active']) {
    http_response_code(404);
    exit('File not found');
}

if (!isAdmin($user) && (int)$row['uploader_id'] !== (int)$user['id']) {
    http_response_code(403);
    exit('Forbidden');
}

$path = (string)$row['file_path'];
$real = realpath($path);
$base = realpath(UPLOAD_DIR);
if ($real === false || $base === false || strpos($real, $base) !== 0 || !is_file($real)) {
    http_response_code(403);
    exit('Access denied');
}

auditLog((int)$user['id'], (int)$row['id'], 'download', ['file' => $row['original_name']]);

header('Content-Type: ' . $row['mime_type']);
header('Content-Length: ' . (string)$row['size_bytes']);
header('X-Content-Type-Options: nosniff');
header('Content-Disposition: attachment; filename="' . basename((string)$row['original_name']) . '"');
readfile($real);
