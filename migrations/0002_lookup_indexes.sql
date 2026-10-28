-- Identity and peer lookups during ingestion (identity keys across sites,
-- flow peers by address): every arm of the candidate query is indexable.
CREATE INDEX assets_ip_any ON assets (tenant_id, ip) WHERE merged_into IS NULL AND deleted_at IS NULL;
CREATE INDEX assets_client_id ON assets (tenant_id, client_id) WHERE client_id IS NOT NULL AND merged_into IS NULL;
CREATE INDEX assets_hostname_any ON assets (tenant_id, lower(hostname)) WHERE hostname IS NOT NULL AND merged_into IS NULL;
CREATE INDEX assets_tls ON assets (tenant_id, tls_fingerprint) WHERE tls_fingerprint IS NOT NULL AND merged_into IS NULL;
