<?php
$page_title = 'Kill Feed — MNM Database';
require __DIR__ . '/includes/header.php';

$db = get_db();
$page = get_page();
$per_page = 50;

// Count
$total = (int)$db->query("SELECT COUNT(*) FROM combat_events WHERE event_type = 'kill'")->fetchColumn();
$total_pages = max(1, (int)ceil($total / $per_page));
$offset = ($page - 1) * $per_page;

$stmt = $db->prepare(
    "SELECT source_name, source_class, source_level,
            target_name, target_class, target_level,
            damage_total, dps, duration_secs, killer_name, created_at
     FROM combat_events
     WHERE event_type = 'kill'
     ORDER BY created_at DESC
     LIMIT :lim OFFSET :off"
);
$stmt->bindValue('lim', $per_page, PDO::PARAM_INT);
$stmt->bindValue('off', $offset, PDO::PARAM_INT);
$stmt->execute();
$kills = $stmt->fetchAll();
?>

<h1>Kill Feed</h1>
<p class="text-dim" style="margin-bottom:1rem">Auto-refreshes every 30 seconds.</p>

<table>
    <thead>
        <tr>
            <th>When</th>
            <th>Killer</th>
            <th>Target</th>
            <th class="text-right">Damage</th>
            <th class="text-right">DPS</th>
            <th class="text-right">Duration</th>
        </tr>
    </thead>
    <tbody>
    <?php foreach ($kills as $k): ?>
        <tr>
            <td class="text-dim"><?= fmt_ago($k['created_at']) ?></td>
            <td>
                <?= h($k['source_name'] ?? $k['killer_name'] ?? '?') ?>
                <?php if ($k['source_class']): ?>
                    <span class="text-teal">[<?= h($k['source_class']) ?>]</span>
                <?php endif; ?>
            </td>
            <td class="text-red">
                <?= h($k['target_name'] ?? '?') ?>
                <?php if ($k['target_class']): ?>
                    <span class="text-dim">[<?= h($k['target_class']) ?>]</span>
                <?php endif; ?>
            </td>
            <td class="text-right text-mono"><?= fmt_num($k['damage_total']) ?></td>
            <td class="text-right text-mono text-peach"><?= $k['dps'] !== null ? number_format((float)$k['dps'], 1) : '—' ?></td>
            <td class="text-right text-mono text-dim"><?= $k['duration_secs'] !== null ? number_format((float)$k['duration_secs'], 1) . 's' : '—' ?></td>
        </tr>
    <?php endforeach; ?>
    <?php if (!$kills): ?>
        <tr><td colspan="6" class="text-center text-dim">No kills recorded yet</td></tr>
    <?php endif; ?>
    </tbody>
</table>

<?= pagination($page, $total_pages, '?x=1') ?>

<script>
setTimeout(function() { location.reload(); }, 30000);
</script>

<?php require __DIR__ . '/includes/footer.php'; ?>
