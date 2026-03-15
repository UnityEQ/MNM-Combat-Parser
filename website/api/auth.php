<?php
/**
 * MNM Combat Parser — API Authentication & Rate Limiting
 *
 * Auth scheme: HMAC-signed requests
 *   X-API-Key:       raw secret key
 *   X-API-Timestamp:  unix timestamp
 *   X-API-Signature:  HMAC-SHA256 of "timestamp:body" using key
 */

require_once __DIR__ . '/../includes/config.php';
require_once __DIR__ . '/../includes/db.php';

/**
 * Authenticate the request. Returns key_hash on success, sends error response on failure.
 */
function authenticate_request(string $body): ?string {
    $api_key   = $_SERVER['HTTP_X_API_KEY']       ?? '';
    $timestamp = $_SERVER['HTTP_X_API_TIMESTAMP'] ?? '';
    $signature = $_SERVER['HTTP_X_API_SIGNATURE'] ?? '';

    if (!$api_key || !$timestamp || !$signature) {
        send_error(401, 'Missing authentication headers');
        return null;
    }

    // Validate timestamp freshness
    $ts = (int)$timestamp;
    if (abs(time() - $ts) > TIMESTAMP_TOLERANCE) {
        send_error(401, 'Timestamp expired');
        return null;
    }

    // Verify HMAC signature
    $expected = hash_hmac('sha256', $timestamp . ':' . $body, $api_key);
    if (!hash_equals($expected, $signature)) {
        send_error(401, 'Invalid signature');
        return null;
    }

    // Check key exists in database
    $key_hash = hash('sha256', $api_key);
    $db = get_db();
    $stmt = $db->prepare('SELECT is_active FROM api_keys WHERE key_hash = :hash');
    $stmt->execute(['hash' => $key_hash]);
    $row = $stmt->fetch();

    if (!$row) {
        send_error(401, 'Unknown API key');
        return null;
    }
    if (!$row['is_active']) {
        send_error(403, 'API key is deactivated');
        return null;
    }

    // Rate limiting
    if (!check_rate_limit($db, $key_hash)) {
        send_error(429, 'Rate limit exceeded');
        return null;
    }

    // Update last_used
    $db->prepare('UPDATE api_keys SET last_used = NOW() WHERE key_hash = :hash')
       ->execute(['hash' => $key_hash]);

    return $key_hash;
}

/**
 * Check and increment rate limit. Returns true if within limits.
 */
function check_rate_limit(PDO $db, string $key_hash): bool {
    $window = date('Y-m-d H:i:00', floor(time() / RATE_LIMIT_WINDOW) * RATE_LIMIT_WINDOW);

    $stmt = $db->prepare(
        'INSERT INTO rate_limits (key_hash, window_start, request_count)
         VALUES (:hash, :window, 1)
         ON CONFLICT (key_hash, window_start)
         DO UPDATE SET request_count = rate_limits.request_count + 1
         RETURNING request_count'
    );
    $stmt->execute(['hash' => $key_hash, 'window' => $window]);
    $count = (int)$stmt->fetchColumn();

    return $count <= RATE_LIMIT_MAX;
}

/**
 * Send a JSON error response and exit.
 */
function send_error(int $code, string $message): void {
    http_response_code($code);
    header('Content-Type: application/json');
    echo json_encode(['error' => $message]);
    exit;
}
