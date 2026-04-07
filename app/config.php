<?php
declare(strict_types=1);

const APP_NAME = 'Secure Vault Pro';
const APP_URL = 'http://localhost/secure-vault-pro/public';

const DB_DSN = 'pgsql:host=127.0.0.1;port=5432;dbname=aryan_projects';
const DB_USER = 'aryan';
const DB_PASS = 'Aryan@123';

const REDIS_HOST = '127.0.0.1';
const REDIS_PORT = 6379;

const STORAGE_DIR = __DIR__ . '/../storage';
const UPLOAD_DIR = STORAGE_DIR . '/uploads';
const LOG_DIR = STORAGE_DIR . '/logs';

const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;
const LIST_CACHE_TTL = 60;
const DASH_CACHE_TTL = 40;

const LOGIN_RATE_LIMIT_PER_MIN = 20;
const UPLOAD_RATE_LIMIT_PER_MIN = 25;

const ALLOWED_EXT_MIME = [
    'jpg' => ['image/jpeg'],
    'jpeg' => ['image/jpeg'],
    'png' => ['image/png'],
    'gif' => ['image/gif'],
    'webp' => ['image/webp'],
    'pdf' => ['application/pdf'],
    'txt' => ['text/plain'],
    'doc' => ['application/msword', 'application/octet-stream'],
    'docx' => ['application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/zip', 'application/octet-stream'],
];
