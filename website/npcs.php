<?php
$page_title = 'NPC Database — MNM Database';
require __DIR__ . '/includes/header.php';

$db = get_db();
$page     = get_page();
$per_page = 50;
$search   = valid_str($_GET['q'] ?? null, 128);
$sort     = $_GET['sort'] ?? 'name';
$dir      = ($_GET['dir'] ?? 'asc') === 'desc' ? 'DESC' : 'ASC';

// Allowed sort columns
$sort_cols = ['name' => 'entity_name', 'level' => 'level', 'hp' => 'max_health', 'seen' => 'last_seen'];
$order_col = $sort_cols[$sort] ?? 'entity_name';

// Build query
$where = [];
$params = [];
if ($search) {
    $where[] = "entity_name ILIKE :q";
    $params['q'] = '%' . $search . '%';
}
$where_sql = $where ? ('WHERE ' . implode(' AND ', $where)) : '';

$count_sql = "SELECT COUNT(*) FROM npcs {$where_sql}";
$stmt = $db->prepare($count_sql);
$stmt->execute($params);
$total = (int)$stmt->fetchColumn();
$total_pages = max(1, (int)ceil($total / $per_page));
$offset = ($page - 1) * $per_page;

$sql = "SELECT id, entity_name, entity_type, class_hid, level, max_health, max_mana, is_hostile, last_seen
        FROM npcs {$where_sql}
        ORDER BY {$order_col} {$dir}
        LIMIT :lim OFFSET :off";
$stmt = $db->prepare($sql);
foreach ($params as $k => $v) {
    $stmt->bindValue($k, $v);
}
$stmt->bindValue('lim', $per_page, PDO::PARAM_INT);
$stmt->bindValue('off', $offset, PDO::PARAM_INT);
$stmt->execute();
$npcs = $stmt->fetchAll();

function sort_link(string $col, string $label, string $current_sort, string $current_dir, ?string $search): string {
    $new_dir = ($current_sort === $col && $current_dir === 'ASC') ? 'desc' : 'asc';
    $arrow = '';
    if ($current_sort === $col) {
        $arrow = $current_dir === 'ASC' ? ' &uarr;' : ' &darr;';
    }
    $q = $search ? '&q=' . urlencode($search) : '';
    return '<a href="?sort=' . $col . '&dir=' . $new_dir . $q . '">' . $label . $arrow . '</a>';
}
?>

<h1>NPC Database</h1>

<form class="filter-bar" method="get">
    <input type="text" name="q" placeholder="Search NPCs..." value="<?= h($search ?? '') ?>" style="width:250px">
    <button type="submit">Search</button>
    <?php if ($search): ?>
        <a href="/npcs.php" style="font-size:0.85rem">Clear</a>
    <?php endif; ?>
</form>

<table>
    <thead>
        <tr>
            <th><?= sort_link('name', 'Name', $sort, $dir, $search) ?></th>
            <th>Class</th>
            <th><?= sort_link('level', 'Level', $sort, $dir, $search) ?></th>
            <th><?= sort_link('hp', 'Max HP', $sort, $dir, $search) ?></th>
            <th>Max Mana</th>
            <th>Hostile</th>
            <th><?= sort_link('seen', 'Last Seen', $sort, $dir, $search) ?></th>
        </tr>
    </thead>
    <tbody>
    <?php foreach ($npcs as $n): ?>
        <tr>
            <td><a href="/npc_detail.php?name=<?= urlencode($n['entity_name']) ?>"><?= h($n['entity_name']) ?></a></td>
            <td class="text-teal"><?= h($n['class_hid'] ?? '') ?></td>
            <td><?= $n['level'] ?? '—' ?></td>
            <td class="text-mono"><?= fmt_num($n['max_health']) ?></td>
            <td class="text-mono"><?= fmt_num($n['max_mana']) ?></td>
            <td>
                <?php if ($n['is_hostile']): ?>
                    <span class="badge badge-hostile">Hostile</span>
                <?php else: ?>
                    <span class="badge badge-passive">Passive</span>
                <?php endif; ?>
            </td>
            <td class="text-dim"><?= fmt_ago($n['last_seen']) ?></td>
        </tr>
    <?php endforeach; ?>
    <?php if (!$npcs): ?>
        <tr><td colspan="7" class="text-center text-dim">No NPCs found</td></tr>
    <?php endif; ?>
    </tbody>
</table>

<?php
$base = '?sort=' . urlencode($sort) . '&dir=' . urlencode(strtolower($dir)) . ($search ? '&q=' . urlencode($search) : '');
echo pagination($page, $total_pages, $base);
?>

<?php require __DIR__ . '/includes/footer.php'; ?>
