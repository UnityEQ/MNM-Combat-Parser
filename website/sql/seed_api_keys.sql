-- Seed API keys for testing
-- Key hash is SHA256 of the raw API key string
--
-- Example: key "test-parser-key-001" has SHA256:
--   echo -n "test-parser-key-001" | sha256sum
--
-- Generate your own production keys and insert their SHA256 hashes here.

INSERT INTO api_keys (key_hash, label) VALUES
    -- test-parser-key-001
    (encode(sha256('test-parser-key-001'::bytea), 'hex'), 'Test Key 1'),
    -- test-parser-key-002
    (encode(sha256('test-parser-key-002'::bytea), 'hex'), 'Test Key 2')
ON CONFLICT (key_hash) DO NOTHING;
