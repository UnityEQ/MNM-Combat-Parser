<?php
$page_title = 'MNM Database — Home';
require __DIR__ . '/includes/header.php';

$db = get_db();

$counts = [];
foreach (['players', 'npcs', 'items', 'combat_events', 'loot_events'] as $tbl) {
    $row = $db->query("SELECT COUNT(*) AS c FROM {$tbl}")->fetch();
    $counts[$tbl] = (int)$row['c'];
}

// Recent activity
$recent_kills = $db->query(
    "SELECT source_name, target_name, damage_total, dps, created_at
     FROM combat_events WHERE event_type = 'kill'
     ORDER BY created_at DESC LIMIT 5"
)->fetchAll();
?>

<h1>Dashboard</h1>

<div class="stat-grid">
    <div class="stat-card">
        <div class="stat-value"><?= fmt_num($counts['players']) ?></div>
        <div class="stat-label">Players Tracked</div>
    </div>
    <div class="stat-card">
        <div class="stat-value"><?= fmt_num($counts['npcs']) ?></div>
        <div class="stat-label">NPCs Catalogued</div>
    </div>
    <div class="stat-card">
        <div class="stat-value"><?= fmt_num($counts['items']) ?></div>
        <div class="stat-label">Items Discovered</div>
    </div>
    <div class="stat-card">
        <div class="stat-value"><?= fmt_num($counts['combat_events']) ?></div>
        <div class="stat-label">Combat Events</div>
    </div>
    <div class="stat-card">
        <div class="stat-value"><?= fmt_num($counts['loot_events']) ?></div>
        <div class="stat-label">Loot Drops</div>
    </div>
</div>

<h2>Recent Kills</h2>
<?php if ($recent_kills): ?>
<table>
    <thead>
        <tr>
            <th>Killer</th>
            <th>Target</th>
            <th class="text-right">Damage</th>
            <th class="text-right">DPS</th>
            <th>When</th>
        </tr>
    </thead>
    <tbody>
    <?php foreach ($recent_kills as $k): ?>
        <tr>
            <td><?= h($k['source_name'] ?? '?') ?></td>
            <td class="text-red"><?= h($k['target_name'] ?? '?') ?></td>
            <td class="text-right text-mono"><?= fmt_num($k['damage_total']) ?></td>
            <td class="text-right text-mono"><?= $k['dps'] !== null ? number_format((float)$k['dps'], 1) : '—' ?></td>
            <td class="text-dim"><?= fmt_ago($k['created_at']) ?></td>
        </tr>
    <?php endforeach; ?>
    </tbody>
</table>
<?php else: ?>
<p class="text-dim">No kills recorded yet. Start your parser to contribute data!</p>
<?php endif; ?>

<?php require __DIR__ . '/includes/footer.php'; ?>
