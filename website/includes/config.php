<?php
/**
 * MNM Combat Parser — Website Configuration
 */

define('DB_HOST', getenv('MNM_DB_HOST') ?: 'localhost');
define('DB_PORT', getenv('MNM_DB_PORT') ?: '5432');
define('DB_NAME', getenv('MNM_DB_NAME') ?: 'mnm');
define('DB_USER', getenv('MNM_DB_USER') ?: 'mnm');
define('DB_PASS', getenv('MNM_DB_PASS') ?: '');

// Rate limiting
define('RATE_LIMIT_MAX',    60);   // requests per window
define('RATE_LIMIT_WINDOW', 60);   // seconds

// Batch size limits per request
define('MAX_COMBAT_EVENTS', 500);
define('MAX_LOOT_EVENTS',   200);
define('MAX_ITEMS',         100);
define('MAX_NPCS',          100);

// Timestamp tolerance for HMAC auth (seconds)
define('TIMESTAMP_TOLERANCE', 300);  // 5 minutes

// Site name
define('SITE_NAME', 'MNM Database');
