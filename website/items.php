<?php
$page_title = 'Item Database — MNM Database';
require __DIR__ . '/includes/header.php';

$db = get_db();
$page     = get_page();
$per_page = 50;
$search   = valid_str($_GET['q'] ?? null, 128);
$sort     = $_GET['sort'] ?? 'name';
$dir      = ($_GET['dir'] ?? 'asc') === 'desc' ? 'DESC' : 'ASC';

$sort_cols = ['name' => 'name', 'damage' => 'damage', 'ac' => 'ac', 'seen' => 'last_seen'];
$order_col = $sort_cols[$sort] ?? 'name';

$where = [];
$params = [];
if ($search) {
    $where[] = "(name ILIKE :q OR hid ILIKE :q)";
    $params['q'] = '%' . $search . '%';
}
$where_sql = $where ? ('WHERE ' . implode(' AND ', $where)) : '';

$stmt = $db->prepare("SELECT COUNT(*) FROM items {$where_sql}");
$stmt->execute($params);
$total = (int)$stmt->fetchColumn();
$total_pages = max(1, (int)ceil($total / $per_page));
$offset = ($page - 1) * $per_page;

$sql = "SELECT hid, name, item_type, damage, ac, required_level,
               no_drop, is_magic, is_unique, last_seen
        FROM items {$where_sql}
        ORDER BY {$order_col} {$dir}
        LIMIT :lim OFFSET :off";
$stmt = $db->prepare($sql);
foreach ($params as $k => $v) {
    $stmt->bindValue($k, $v);
}
$stmt->bindValue('lim', $per_page, PDO::PARAM_INT);
$stmt->bindValue('off', $offset, PDO::PARAM_INT);
$stmt->execute();
$items = $stmt->fetchAll();

function item_sort_link(string $col, string $label, string $cur_sort, string $cur_dir, ?string $search): string {
    $new_dir = ($cur_sort === $col && $cur_dir === 'ASC') ? 'desc' : 'asc';
    $arrow = ($cur_sort === $col) ? ($cur_dir === 'ASC' ? ' &uarr;' : ' &darr;') : '';
    $q = $search ? '&q=' . urlencode($search) : '';
    return '<a href="?sort=' . $col . '&dir=' . $new_dir . $q . '">' . $label . $arrow . '</a>';
}
?>

<h1>Item Database</h1>

<form class="filter-bar" method="get">
    <input type="text" name="q" placeholder="Search items..." value="<?= h($search ?? '') ?>" style="width:250px">
    <button type="submit">Search</button>
    <?php if ($search): ?>
        <a href="/items.php" style="font-size:0.85rem">Clear</a>
    <?php endif; ?>
</form>

<table>
    <thead>
        <tr>
            <th><?= item_sort_link('name', 'Name', $sort, $dir, $search) ?></th>
            <th><?= item_sort_link('damage', 'Damage', $sort, $dir, $search) ?></th>
            <th><?= item_sort_link('ac', 'AC', $sort, $dir, $search) ?></th>
            <th>Req Lvl</th>
            <th>Flags</th>
            <th><?= item_sort_link('seen', 'Last Seen', $sort, $dir, $search) ?></th>
        </tr>
    </thead>
    <tbody>
    <?php foreach ($items as $item): ?>
        <tr>
            <td>
                <a href="/item_detail.php?hid=<?= urlencode($item['hid']) ?>">
                    <?= h($item['name'] ?? $item['hid']) ?>
                </a>
                <?php if ($item['is_magic']): ?>
                    <span class="text-mauve">*</span>
                <?php endif; ?>
            </td>
            <td class="text-mono"><?= $item['damage'] ? fmt_num($item['damage']) : '—' ?></td>
            <td class="text-mono"><?= $item['ac'] ? fmt_num($item['ac']) : '—' ?></td>
            <td><?= $item['required_level'] ?? '—' ?></td>
            <td class="text-dim">
                <?= $item['no_drop'] ? 'ND ' : '' ?>
                <?= $item['is_unique'] ? 'UQ ' : '' ?>
            </td>
            <td class="text-dim"><?= fmt_ago($item['last_seen']) ?></td>
        </tr>
    <?php endforeach; ?>
    <?php if (!$items): ?>
        <tr><td colspan="6" class="text-center text-dim">No items found</td></tr>
    <?php endif; ?>
    </tbody>
</table>

<?php
$base = '?sort=' . urlencode($sort) . '&dir=' . urlencode(strtolower($dir)) . ($search ? '&q=' . urlencode($search) : '');
echo pagination($page, $total_pages, $base);
?>

<?php require __DIR__ . '/includes/footer.php'; ?>
