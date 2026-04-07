-- Secure Vault Pro schema (PostgreSQL)
ALTER TABLE app_users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user';
ALTER TABLE app_users ADD COLUMN IF NOT EXISTS password_hash TEXT;
ALTER TABLE app_users ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE app_users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS uploaded_assets (
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
);

CREATE INDEX IF NOT EXISTS idx_uploaded_assets_created_at ON uploaded_assets(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_uploaded_assets_uploader_created ON uploaded_assets(uploader_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_uploaded_assets_mime_created ON uploaded_assets(mime_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_uploaded_assets_lower_name ON uploaded_assets((lower(original_name)));

CREATE TABLE IF NOT EXISTS asset_audit_logs (
  id BIGSERIAL PRIMARY KEY,
  actor_user_id INT REFERENCES app_users(id),
  asset_id BIGINT,
  action TEXT NOT NULL,
  details JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_asset_logs_created ON asset_audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_asset_logs_actor ON asset_audit_logs(actor_user_id, created_at DESC);
