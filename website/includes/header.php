<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/functions.php';

$current_page_file = basename($_SERVER['SCRIPT_NAME']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= h($page_title ?? SITE_NAME) ?></title>
    <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
<header class="site-header">
    <span class="logo"><?= h(SITE_NAME) ?></span>
    <nav>
        <a href="/" class="<?= $current_page_file === 'index.php' ? 'active' : '' ?>">Home</a>
        <a href="/leaderboard.php" class="<?= $current_page_file === 'leaderboard.php' ? 'active' : '' ?>">Leaderboard</a>
        <a href="/killfeed.php" class="<?= $current_page_file === 'killfeed.php' ? 'active' : '' ?>">Kill Feed</a>
        <a href="/npcs.php" class="<?= $current_page_file === 'npcs.php' ? 'active' : '' ?>">NPCs</a>
        <a href="/items.php" class="<?= $current_page_file === 'items.php' ? 'active' : '' ?>">Items</a>
    </nav>
</header>
<div class="container">
