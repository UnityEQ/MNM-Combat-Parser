<?php
/**
 * MNM Combat Parser — Shared utility functions
 */

/**
 * Escape HTML for safe output.
 */
function h(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

/**
 * Format a timestamp for display.
 */
function fmt_time(?string $ts): string {
    if (!$ts) return '—';
    $dt = new DateTime($ts);
    return $dt->format('M j, Y H:i');
}

/**
 * Format a timestamp as relative time (e.g. "3m ago").
 */
function fmt_ago(?string $ts): string {
    if (!$ts) return '—';
    $dt = new DateTime($ts);
    $now = new DateTime();
    $diff = $now->getTimestamp() - $dt->getTimestamp();
    if ($diff < 60)   return $diff . 's ago';
    if ($diff < 3600)  return floor($diff / 60) . 'm ago';
    if ($diff < 86400) return floor($diff / 3600) . 'h ago';
    return floor($diff / 86400) . 'd ago';
}

/**
 * Format a number with commas.
 */
function fmt_num($n): string {
    if ($n === null) return '—';
    return number_format((int)$n);
}

/**
 * Get current page number from query string, clamped to >= 1.
 */
function get_page(): int {
    return max(1, (int)($_GET['page'] ?? 1));
}

/**
 * Build pagination HTML.
 */
function pagination(int $current_page, int $total_pages, string $base_url): string {
    if ($total_pages <= 1) return '';
    $html = '<div class="pagination">';
    if ($current_page > 1) {
        $html .= '<a href="' . h($base_url) . '&page=' . ($current_page - 1) . '">&laquo; Prev</a>';
    }
    $start = max(1, $current_page - 3);
    $end   = min($total_pages, $current_page + 3);
    for ($i = $start; $i <= $end; $i++) {
        if ($i === $current_page) {
            $html .= '<span class="current">' . $i . '</span>';
        } else {
            $html .= '<a href="' . h($base_url) . '&page=' . $i . '">' . $i . '</a>';
        }
    }
    if ($current_page < $total_pages) {
        $html .= '<a href="' . h($base_url) . '&page=' . ($current_page + 1) . '">Next &raquo;</a>';
    }
    $html .= '</div>';
    return $html;
}

/**
 * Validate a string field: non-empty, max length, printable.
 */
function valid_str(?string $s, int $max_len): ?string {
    if ($s === null || $s === '') return null;
    $s = mb_substr(trim($s), 0, $max_len, 'UTF-8');
    // Strip control characters except newline/tab
    $s = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $s);
    return $s !== '' ? $s : null;
}

/**
 * Validate an integer in range.
 */
function valid_int($v, int $min, int $max): ?int {
    if ($v === null || $v === '') return null;
    $i = filter_var($v, FILTER_VALIDATE_INT);
    if ($i === false || $i < $min || $i > $max) return null;
    return $i;
}

/**
 * Validate a float in range.
 */
function valid_float($v, float $min, float $max): ?float {
    if ($v === null || $v === '') return null;
    $f = filter_var($v, FILTER_VALIDATE_FLOAT);
    if ($f === false || $f < $min || $f > $max) return null;
    return $f;
}
