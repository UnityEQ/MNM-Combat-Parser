<?php
$page_title = 'Leaderboard — MNM Database';
require __DIR__ . '/includes/header.php';

$db = get_db();

// Filters
$class_filter = valid_str($_GET['class'] ?? null, 16);
$period       = $_GET['period'] ?? 'all';
$page         = get_page();
$per_page     = 50;

// Build WHERE clauses
$where = ["event_type = 'kill'", "source_name IS NOT NULL"];
$params = [];

if ($class_filter) {
    $where[] = "source_class = :cls";
    $params['cls'] = $class_filter;
}

if ($period === '24h') {
    $where[] = "created_at > NOW() - INTERVAL '24 hours'";
} elseif ($period === '7d') {
    $where[] = "created_at > NOW() - INTERVAL '7 days'";
} elseif ($period === '30d') {
    $where[] = "created_at > NOW() - INTERVAL '30 days'";
}

$where_sql = implode(' AND ', $where);

// Count
$count_sql = "SELECT COUNT(DISTINCT source_name) FROM combat_events WHERE {$where_sql}";
$stmt = $db->prepare($count_sql);
$stmt->execute($params);
$total = (int)$stmt->fetchColumn();
$total_pages = max(1, (int)ceil($total / $per_page));
$offset = ($page - 1) * $per_page;

// Query
$sql = "SELECT
            source_name,
            source_class,
            MAX(source_level) AS max_level,
            COUNT(*) AS kill_count,
            MAX(dps) AS best_dps,
            AVG(dps) AS avg_dps,
            SUM(damage_total) AS total_damage
        FROM combat_events
        WHERE {$where_sql}
        GROUP BY source_name, source_class
        ORDER BY best_dps DESC
        LIMIT :lim OFFSET :off";

$stmt = $db->prepare($sql);
foreach ($params as $k => $v) {
    $stmt->bindValue($k, $v);
}
$stmt->bindValue('lim', $per_page, PDO::PARAM_INT);
$stmt->bindValue('off', $offset, PDO::PARAM_INT);
$stmt->execute();
$rows = $stmt->fetchAll();

// Max DPS for bar scaling
$max_dps = $rows ? (float)$rows[0]['best_dps'] : 1;

// Available classes
$classes = $db->query("SELECT DISTINCT source_class FROM combat_events WHERE source_class IS NOT NULL AND source_class != '' ORDER BY source_class")->fetchAll(PDO::FETCH_COLUMN);
?>

<h1>DPS Leaderboard</h1>

<form class="filter-bar" method="get">
    <select name="class">
        <option value="">All Classes</option>
        <?php foreach ($classes as $c): ?>
        <option value="<?= h($c) ?>" <?= $class_filter === $c ? 'selected' : '' ?>><?= h($c) ?></option>
        <?php endforeach; ?>
    </select>
    <select name="period">
        <option value="all" <?= $period === 'all' ? 'selected' : '' ?>>All Time</option>
        <option value="24h" <?= $period === '24h' ? 'selected' : '' ?>>Last 24h</option>
        <option value="7d" <?= $period === '7d' ? 'selected' : '' ?>>Last 7 Days</option>
        <option value="30d" <?= $period === '30d' ? 'selected' : '' ?>>Last 30 Days</option>
    </select>
    <button type="submit">Filter</button>
</form>

<table>
    <thead>
        <tr>
            <th>#</th>
            <th>Player</th>
            <th>Class</th>
            <th>Level</th>
            <th>Best DPS</th>
            <th>DPS</th>
            <th class="text-right">Avg DPS</th>
            <th class="text-right">Kills</th>
            <th class="text-right">Total Damage</th>
        </tr>
    </thead>
    <tbody>
    <?php foreach ($rows as $i => $r): ?>
        <?php $pct = $max_dps > 0 ? ((float)$r['best_dps'] / $max_dps * 100) : 0; ?>
        <tr>
            <td class="text-dim"><?= $offset + $i + 1 ?></td>
            <td><?= h($r['source_name']) ?></td>
            <td class="text-teal"><?= h($r['source_class'] ?? '') ?></td>
            <td><?= $r['max_level'] ?? '—' ?></td>
            <td class="text-mono text-peach"><?= number_format((float)$r['best_dps'], 1) ?></td>
            <td style="min-width:120px">
                <div class="dps-bar-container">
                    <div class="dps-bar" style="width:<?= round($pct, 1) ?>%"></div>
                </div>
            </td>
            <td class="text-right text-mono"><?= number_format((float)$r['avg_dps'], 1) ?></td>
            <td class="text-right"><?= fmt_num($r['kill_count']) ?></td>
            <td class="text-right text-mono"><?= fmt_num($r['total_damage']) ?></td>
        </tr>
    <?php endforeach; ?>
    <?php if (!$rows): ?>
        <tr><td colspan="9" class="text-center text-dim">No data yet</td></tr>
    <?php endif; ?>
    </tbody>
</table>

<?php
$base = '?class=' . urlencode($class_filter ?? '') . '&period=' . urlencode($period);
echo pagination($page, $total_pages, $base);
?>

<?php require __DIR__ . '/includes/footer.php'; ?>
