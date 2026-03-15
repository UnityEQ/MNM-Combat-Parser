<?php
require __DIR__ . '/includes/header.php';

$db = get_db();
$name = valid_str($_GET['name'] ?? null, 128);
if (!$name) {
    echo '<p class="text-red">No NPC specified.</p>';
    require __DIR__ . '/includes/footer.php';
    exit;
}

$page_title = h($name) . ' — NPC — MNM Database';

// Fetch NPC rows (may have multiple levels)
$stmt = $db->prepare("SELECT * FROM npcs WHERE entity_name = :name ORDER BY level ASC");
$stmt->execute(['name' => $name]);
$npcs = $stmt->fetchAll();

if (!$npcs) {
    echo '<p class="text-red">NPC not found.</p>';
    require __DIR__ . '/includes/footer.php';
    exit;
}

// Use the highest-level variant as primary
$npc = $npcs[count($npcs) - 1];

// Loot table for this NPC
$stmt = $db->prepare(
    "SELECT item_hid, item_name, COUNT(*) AS drop_count, SUM(quantity) AS total_qty
     FROM loot_events
     WHERE npc_name = :name
     GROUP BY item_hid, item_name
     ORDER BY drop_count DESC
     LIMIT 50"
);
$stmt->execute(['name' => $name]);
$loot = $stmt->fetchAll();

// Kill history
$stmt = $db->prepare(
    "SELECT source_name, source_class, damage_total, dps, created_at
     FROM combat_events
     WHERE event_type = 'kill' AND target_name = :name
     ORDER BY created_at DESC
     LIMIT 20"
);
$stmt->execute(['name' => $name]);
$kills = $stmt->fetchAll();
?>

<div class="detail-header">
    <h1><?= h($npc['entity_name']) ?></h1>
    <div class="meta">
        <?php if ($npc['class_hid']): ?>
            <span class="text-teal">[<?= h($npc['class_hid']) ?>]</span>
        <?php endif; ?>
        <?php if ($npc['is_hostile']): ?>
            <span class="badge badge-hostile">Hostile</span>
        <?php else: ?>
            <span class="badge badge-passive">Passive</span>
        <?php endif; ?>
        &mdash; Last seen <?= fmt_ago($npc['last_seen']) ?>
    </div>
</div>

<?php if (count($npcs) > 1): ?>
<h2>Variants by Level</h2>
<table>
    <thead>
        <tr><th>Level</th><th>Max HP</th><th>Max Mana</th><th>Class</th><th>Hostile</th></tr>
    </thead>
    <tbody>
    <?php foreach ($npcs as $v): ?>
        <tr>
            <td><?= $v['level'] ?? '—' ?></td>
            <td class="text-mono"><?= fmt_num($v['max_health']) ?></td>
            <td class="text-mono"><?= fmt_num($v['max_mana']) ?></td>
            <td class="text-teal"><?= h($v['class_hid'] ?? '') ?></td>
            <td><?= $v['is_hostile'] ? 'Yes' : 'No' ?></td>
        </tr>
    <?php endforeach; ?>
    </tbody>
</table>
<?php else: ?>
<div class="stat-list">
    <div class="stat-item"><span class="label">Level</span><span class="value"><?= $npc['level'] ?? '—' ?></span></div>
    <div class="stat-item"><span class="label">Max HP</span><span class="value"><?= fmt_num($npc['max_health']) ?></span></div>
    <div class="stat-item"><span class="label">Max Mana</span><span class="value"><?= fmt_num($npc['max_mana']) ?></span></div>
</div>
<?php endif; ?>

<?php if ($loot): ?>
<h2>Loot Table</h2>
<table>
    <thead>
        <tr><th>Item</th><th class="text-right">Times Dropped</th><th class="text-right">Total Qty</th></tr>
    </thead>
    <tbody>
    <?php foreach ($loot as $l): ?>
        <tr>
            <td>
                <?php if ($l['item_hid']): ?>
                    <a href="/item_detail.php?hid=<?= urlencode($l['item_hid']) ?>"><?= h($l['item_name']) ?></a>
                <?php else: ?>
                    <?= h($l['item_name']) ?>
                <?php endif; ?>
            </td>
            <td class="text-right"><?= fmt_num($l['drop_count']) ?></td>
            <td class="text-right"><?= fmt_num($l['total_qty']) ?></td>
        </tr>
    <?php endforeach; ?>
    </tbody>
</table>
<?php endif; ?>

<?php if ($kills): ?>
<h2>Recent Kills</h2>
<table>
    <thead>
        <tr><th>Killer</th><th>Class</th><th class="text-right">Damage</th><th class="text-right">DPS</th><th>When</th></tr>
    </thead>
    <tbody>
    <?php foreach ($kills as $k): ?>
        <tr>
            <td><?= h($k['source_name'] ?? '?') ?></td>
            <td class="text-teal"><?= h($k['source_class'] ?? '') ?></td>
            <td class="text-right text-mono"><?= fmt_num($k['damage_total']) ?></td>
            <td class="text-right text-mono"><?= $k['dps'] !== null ? number_format((float)$k['dps'], 1) : '—' ?></td>
            <td class="text-dim"><?= fmt_ago($k['created_at']) ?></td>
        </tr>
    <?php endforeach; ?>
    </tbody>
</table>
<?php endif; ?>

<?php require __DIR__ . '/includes/footer.php'; ?>
