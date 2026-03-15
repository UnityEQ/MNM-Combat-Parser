<?php
require __DIR__ . '/includes/header.php';

$db = get_db();
$hid = valid_str($_GET['hid'] ?? null, 128);
if (!$hid) {
    echo '<p class="text-red">No item specified.</p>';
    require __DIR__ . '/includes/footer.php';
    exit;
}

$stmt = $db->prepare("SELECT * FROM items WHERE hid = :hid");
$stmt->execute(['hid' => $hid]);
$item = $stmt->fetch();

if (!$item) {
    echo '<p class="text-red">Item not found.</p>';
    require __DIR__ . '/includes/footer.php';
    exit;
}

$page_title = h($item['name'] ?? $hid) . ' — Item — MNM Database';

// Drop sources
$stmt = $db->prepare(
    "SELECT npc_name, COUNT(*) AS drop_count, SUM(quantity) AS total_qty
     FROM loot_events
     WHERE item_hid = :hid
     GROUP BY npc_name
     ORDER BY drop_count DESC
     LIMIT 30"
);
$stmt->execute(['hid' => $hid]);
$sources = $stmt->fetchAll();

// Recent loot events
$stmt = $db->prepare(
    "SELECT player_name, player_class, npc_name, quantity, created_at
     FROM loot_events
     WHERE item_hid = :hid
     ORDER BY created_at DESC
     LIMIT 20"
);
$stmt->execute(['hid' => $hid]);
$recent = $stmt->fetchAll();

// Stat display helper
$stat_fields = [
    'damage' => 'Damage', 'delay' => 'Delay', 'ac' => 'AC',
    'strength' => 'STR', 'stamina' => 'STA', 'dexterity' => 'DEX',
    'agility' => 'AGI', 'intelligence' => 'INT', 'wisdom' => 'WIS', 'charisma' => 'CHA',
    'health' => 'HP', 'health_regen' => 'HP Regen', 'mana' => 'Mana', 'mana_regen' => 'Mana Regen',
    'melee_haste' => 'Melee Haste', 'ranged_haste' => 'Ranged Haste', 'spell_haste' => 'Spell Haste',
    'resist_fire' => 'Fire Resist', 'resist_cold' => 'Cold Resist',
    'resist_poison' => 'Poison Resist', 'resist_disease' => 'Disease Resist',
    'resist_magic' => 'Magic Resist', 'resist_arcane' => 'Arcane Resist',
    'resist_nature' => 'Nature Resist', 'resist_holy' => 'Holy Resist',
    'weight' => 'Weight',
];
?>

<div class="detail-header">
    <h1>
        <?= h($item['name'] ?? $hid) ?>
        <?php if ($item['is_magic']): ?>
            <span class="text-mauve">(Magic)</span>
        <?php endif; ?>
    </h1>
    <div class="meta">
        <span class="text-dim text-mono"><?= h($item['hid']) ?></span>
        <?php if ($item['no_drop']): ?><span class="text-red">NO DROP</span><?php endif; ?>
        <?php if ($item['is_unique']): ?><span class="text-yellow">UNIQUE</span><?php endif; ?>
        <?php if ($item['required_level']): ?>&mdash; Req Level: <?= (int)$item['required_level'] ?><?php endif; ?>
    </div>
</div>

<h2>Stats</h2>
<div class="stat-list">
<?php foreach ($stat_fields as $field => $label): ?>
    <?php
    $val = $item[$field];
    if ($val === null || $val == 0) continue;
    $css = '';
    if (is_numeric($val) && $val > 0 && $field !== 'weight' && $field !== 'delay' && $field !== 'damage') $css = ' positive';
    if (is_numeric($val) && $val < 0) $css = ' negative';
    ?>
    <div class="stat-item">
        <span class="label"><?= $label ?></span>
        <span class="value<?= $css ?>"><?= is_float($val + 0) ? number_format((float)$val, 1) : fmt_num($val) ?></span>
    </div>
<?php endforeach; ?>
</div>

<?php if ($item['description']): ?>
<div style="margin-bottom:1.5rem">
    <h2>Description</h2>
    <p class="text-dim" style="padding:0.5rem;background:var(--ctp-surface0);border-radius:6px;font-size:0.9rem">
        <?= nl2br(h($item['description'])) ?>
    </p>
</div>
<?php endif; ?>

<?php
$effects = $item['effects'] ? json_decode($item['effects'], true) : null;
if ($effects && is_array($effects)):
?>
<div style="margin-bottom:1.5rem">
    <h2>Effects</h2>
    <ul style="list-style:disc;padding-left:1.5rem">
    <?php foreach ($effects as $eff): ?>
        <li class="text-yellow"><?= h($eff) ?></li>
    <?php endforeach; ?>
    </ul>
</div>
<?php endif; ?>

<?php if ($sources): ?>
<h2>Drop Sources</h2>
<table>
    <thead>
        <tr><th>NPC</th><th class="text-right">Times Dropped</th><th class="text-right">Total Qty</th></tr>
    </thead>
    <tbody>
    <?php foreach ($sources as $s): ?>
        <tr>
            <td>
                <?php if ($s['npc_name']): ?>
                    <a href="/npc_detail.php?name=<?= urlencode($s['npc_name']) ?>"><?= h($s['npc_name']) ?></a>
                <?php else: ?>
                    <span class="text-dim">Unknown</span>
                <?php endif; ?>
            </td>
            <td class="text-right"><?= fmt_num($s['drop_count']) ?></td>
            <td class="text-right"><?= fmt_num($s['total_qty']) ?></td>
        </tr>
    <?php endforeach; ?>
    </tbody>
</table>
<?php endif; ?>

<?php if ($recent): ?>
<h2>Recent Drops</h2>
<table>
    <thead>
        <tr><th>Player</th><th>Class</th><th>From NPC</th><th>Qty</th><th>When</th></tr>
    </thead>
    <tbody>
    <?php foreach ($recent as $r): ?>
        <tr>
            <td><?= h($r['player_name'] ?? '?') ?></td>
            <td class="text-teal"><?= h($r['player_class'] ?? '') ?></td>
            <td><?= h($r['npc_name'] ?? '?') ?></td>
            <td><?= (int)$r['quantity'] ?></td>
            <td class="text-dim"><?= fmt_ago($r['created_at']) ?></td>
        </tr>
    <?php endforeach; ?>
    </tbody>
</table>
<?php endif; ?>

<?php require __DIR__ . '/includes/footer.php'; ?>
