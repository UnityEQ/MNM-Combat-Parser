<?php
/**
 * MNM Combat Parser — Data Submission API
 *
 * POST /api/submit.php
 *
 * JSON payload with optional arrays: combat_events, loot_events, items, npcs
 * Authenticated via HMAC (see auth.php).
 */

require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/../includes/functions.php';

// Only accept POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    send_error(405, 'Method not allowed');
}

// Read and validate body
$body = file_get_contents('php://input');
if (!$body || strlen($body) > 1_000_000) {
    send_error(400, 'Invalid or oversized request body');
}

// Authenticate
$key_hash = authenticate_request($body);
if (!$key_hash) {
    exit; // auth already sent error
}

// Parse JSON
$data = json_decode($body, true);
if (!is_array($data)) {
    send_error(400, 'Invalid JSON');
}

// Version check
$version = (int)($data['version'] ?? 0);
if ($version !== 1) {
    send_error(400, 'Unsupported payload version');
}

$db = get_db();
$submitter = substr($key_hash, 0, 16); // short hash for submitter_hash column
$counts = ['combat_events' => 0, 'loot_events' => 0, 'items' => 0, 'npcs' => 0];

try {
    $db->beginTransaction();

    // --- Combat events ---
    if (!empty($data['combat_events']) && is_array($data['combat_events'])) {
        $events = array_slice($data['combat_events'], 0, MAX_COMBAT_EVENTS);
        $stmt = $db->prepare(
            'INSERT INTO combat_events
                (event_type, source_name, source_class, source_level,
                 target_name, target_class, target_level,
                 damage_total, dps, healing_total, duration_secs,
                 killer_name, pos_x, pos_y, pos_z, submitter_hash)
             VALUES
                (:event_type, :source_name, :source_class, :source_level,
                 :target_name, :target_class, :target_level,
                 :damage_total, :dps, :healing_total, :duration_secs,
                 :killer_name, :pos_x, :pos_y, :pos_z, :submitter_hash)'
        );

        foreach ($events as $e) {
            if (!is_array($e)) continue;
            $event_type = valid_str($e['event_type'] ?? '', 32);
            if (!$event_type || !in_array($event_type, ['kill', 'dps_snapshot'])) continue;

            $stmt->execute([
                'event_type'    => $event_type,
                'source_name'   => valid_str($e['source_name']  ?? null, 64),
                'source_class'  => valid_str($e['source_class'] ?? null, 16),
                'source_level'  => valid_int($e['source_level'] ?? null, 0, 500),
                'target_name'   => valid_str($e['target_name']  ?? null, 64),
                'target_class'  => valid_str($e['target_class'] ?? null, 16),
                'target_level'  => valid_int($e['target_level'] ?? null, 0, 500),
                'damage_total'  => valid_int($e['damage_total'] ?? null, 0, 100_000_000),
                'dps'           => valid_float($e['dps']           ?? null, 0, 1_000_000),
                'healing_total' => valid_int($e['healing_total'] ?? null, 0, 100_000_000),
                'duration_secs' => valid_float($e['duration_secs'] ?? null, 0, 86400),
                'killer_name'   => valid_str($e['killer_name']  ?? null, 64),
                'pos_x'         => valid_float($e['pos_x'] ?? null, -100000, 100000),
                'pos_y'         => valid_float($e['pos_y'] ?? null, -100000, 100000),
                'pos_z'         => valid_float($e['pos_z'] ?? null, -100000, 100000),
                'submitter_hash'=> $submitter,
            ]);
            $counts['combat_events']++;
        }
    }

    // --- Loot events ---
    if (!empty($data['loot_events']) && is_array($data['loot_events'])) {
        $loots = array_slice($data['loot_events'], 0, MAX_LOOT_EVENTS);
        $stmt = $db->prepare(
            'INSERT INTO loot_events
                (player_name, player_class, player_level,
                 item_hid, item_name, npc_name, quantity, submitter_hash)
             VALUES
                (:player_name, :player_class, :player_level,
                 :item_hid, :item_name, :npc_name, :quantity, :submitter_hash)'
        );

        foreach ($loots as $l) {
            if (!is_array($l)) continue;
            $item_name = valid_str($l['item_name'] ?? null, 128);
            if (!$item_name) continue;

            $stmt->execute([
                'player_name'  => valid_str($l['player_name']  ?? null, 64),
                'player_class' => valid_str($l['player_class'] ?? null, 16),
                'player_level' => valid_int($l['player_level'] ?? null, 0, 500),
                'item_hid'     => valid_str($l['item_hid']     ?? null, 128),
                'item_name'    => $item_name,
                'npc_name'     => valid_str($l['npc_name']     ?? null, 128),
                'quantity'     => valid_int($l['quantity']      ?? 1, 1, 10000) ?? 1,
                'submitter_hash'=> $submitter,
            ]);
            $counts['loot_events']++;
        }
    }

    // --- Items (upsert) ---
    if (!empty($data['items']) && is_array($data['items'])) {
        $items = array_slice($data['items'], 0, MAX_ITEMS);
        $stmt = $db->prepare(
            'INSERT INTO items
                (hid, name, item_type, class_mask, race_mask, slot_mask,
                 required_level, no_drop, is_unique, is_magic, stack_size, charges,
                 damage, delay, ac,
                 strength, stamina, dexterity, agility, intelligence, wisdom, charisma,
                 health, health_regen, mana, mana_regen,
                 melee_haste, ranged_haste, spell_haste,
                 resist_fire, resist_cold, resist_poison, resist_disease,
                 resist_magic, resist_arcane, resist_nature, resist_holy,
                 weight, description, effects, last_seen)
             VALUES
                (:hid, :name, :item_type, :class_mask, :race_mask, :slot_mask,
                 :required_level, :no_drop, :is_unique, :is_magic, :stack_size, :charges,
                 :damage, :delay, :ac,
                 :strength, :stamina, :dexterity, :agility, :intelligence, :wisdom, :charisma,
                 :health, :health_regen, :mana, :mana_regen,
                 :melee_haste, :ranged_haste, :spell_haste,
                 :resist_fire, :resist_cold, :resist_poison, :resist_disease,
                 :resist_magic, :resist_arcane, :resist_nature, :resist_holy,
                 :weight, :description, :effects, NOW())
             ON CONFLICT (hid) DO UPDATE SET
                name = COALESCE(EXCLUDED.name, items.name),
                item_type = COALESCE(EXCLUDED.item_type, items.item_type),
                class_mask = COALESCE(EXCLUDED.class_mask, items.class_mask),
                race_mask = COALESCE(EXCLUDED.race_mask, items.race_mask),
                slot_mask = COALESCE(EXCLUDED.slot_mask, items.slot_mask),
                required_level = COALESCE(EXCLUDED.required_level, items.required_level),
                no_drop = EXCLUDED.no_drop,
                is_unique = EXCLUDED.is_unique,
                is_magic = EXCLUDED.is_magic,
                stack_size = COALESCE(EXCLUDED.stack_size, items.stack_size),
                charges = COALESCE(EXCLUDED.charges, items.charges),
                damage = COALESCE(EXCLUDED.damage, items.damage),
                delay = COALESCE(EXCLUDED.delay, items.delay),
                ac = COALESCE(EXCLUDED.ac, items.ac),
                strength = COALESCE(EXCLUDED.strength, items.strength),
                stamina = COALESCE(EXCLUDED.stamina, items.stamina),
                dexterity = COALESCE(EXCLUDED.dexterity, items.dexterity),
                agility = COALESCE(EXCLUDED.agility, items.agility),
                intelligence = COALESCE(EXCLUDED.intelligence, items.intelligence),
                wisdom = COALESCE(EXCLUDED.wisdom, items.wisdom),
                charisma = COALESCE(EXCLUDED.charisma, items.charisma),
                health = COALESCE(EXCLUDED.health, items.health),
                health_regen = COALESCE(EXCLUDED.health_regen, items.health_regen),
                mana = COALESCE(EXCLUDED.mana, items.mana),
                mana_regen = COALESCE(EXCLUDED.mana_regen, items.mana_regen),
                melee_haste = COALESCE(EXCLUDED.melee_haste, items.melee_haste),
                ranged_haste = COALESCE(EXCLUDED.ranged_haste, items.ranged_haste),
                spell_haste = COALESCE(EXCLUDED.spell_haste, items.spell_haste),
                resist_fire = COALESCE(EXCLUDED.resist_fire, items.resist_fire),
                resist_cold = COALESCE(EXCLUDED.resist_cold, items.resist_cold),
                resist_poison = COALESCE(EXCLUDED.resist_poison, items.resist_poison),
                resist_disease = COALESCE(EXCLUDED.resist_disease, items.resist_disease),
                resist_magic = COALESCE(EXCLUDED.resist_magic, items.resist_magic),
                resist_arcane = COALESCE(EXCLUDED.resist_arcane, items.resist_arcane),
                resist_nature = COALESCE(EXCLUDED.resist_nature, items.resist_nature),
                resist_holy = COALESCE(EXCLUDED.resist_holy, items.resist_holy),
                weight = COALESCE(EXCLUDED.weight, items.weight),
                description = COALESCE(EXCLUDED.description, items.description),
                effects = COALESCE(EXCLUDED.effects, items.effects),
                last_seen = NOW()'
        );

        foreach ($items as $item) {
            if (!is_array($item)) continue;
            $hid = valid_str($item['hid'] ?? null, 128);
            if (!$hid) continue;

            $stmt->execute([
                'hid'            => $hid,
                'name'           => valid_str($item['name'] ?? null, 128),
                'item_type'      => valid_int($item['item_type'] ?? null, 0, 32767),
                'class_mask'     => valid_int($item['class_mask'] ?? null, 0, 2147483647),
                'race_mask'      => valid_int($item['race_mask'] ?? null, 0, 2147483647),
                'slot_mask'      => valid_int($item['slot_mask'] ?? null, 0, 2147483647),
                'required_level' => valid_int($item['required_level'] ?? null, 0, 500),
                'no_drop'        => !empty($item['no_drop']),
                'is_unique'      => !empty($item['is_unique']),
                'is_magic'       => !empty($item['is_magic']),
                'stack_size'     => valid_int($item['stack_size'] ?? null, 0, 32767),
                'charges'        => valid_int($item['charges'] ?? null, 0, 32767),
                'damage'         => valid_int($item['damage'] ?? null, 0, 100000),
                'delay'          => valid_int($item['delay'] ?? null, 0, 100000),
                'ac'             => valid_int($item['ac'] ?? null, 0, 100000),
                'strength'       => valid_int($item['strength'] ?? null, -10000, 10000),
                'stamina'        => valid_int($item['stamina'] ?? null, -10000, 10000),
                'dexterity'      => valid_int($item['dexterity'] ?? null, -10000, 10000),
                'agility'        => valid_int($item['agility'] ?? null, -10000, 10000),
                'intelligence'   => valid_int($item['intelligence'] ?? null, -10000, 10000),
                'wisdom'         => valid_int($item['wisdom'] ?? null, -10000, 10000),
                'charisma'       => valid_int($item['charisma'] ?? null, -10000, 10000),
                'health'         => valid_int($item['health'] ?? null, -100000, 100000),
                'health_regen'   => valid_int($item['health_regen'] ?? null, -100000, 100000),
                'mana'           => valid_int($item['mana'] ?? null, -100000, 100000),
                'mana_regen'     => valid_int($item['mana_regen'] ?? null, -100000, 100000),
                'melee_haste'    => valid_int($item['melee_haste'] ?? null, -10000, 10000),
                'ranged_haste'   => valid_int($item['ranged_haste'] ?? null, -10000, 10000),
                'spell_haste'    => valid_int($item['spell_haste'] ?? null, -10000, 10000),
                'resist_fire'    => valid_int($item['resist_fire'] ?? null, -10000, 10000),
                'resist_cold'    => valid_int($item['resist_cold'] ?? null, -10000, 10000),
                'resist_poison'  => valid_int($item['resist_poison'] ?? null, -10000, 10000),
                'resist_disease' => valid_int($item['resist_disease'] ?? null, -10000, 10000),
                'resist_magic'   => valid_int($item['resist_magic'] ?? null, -10000, 10000),
                'resist_arcane'  => valid_int($item['resist_arcane'] ?? null, -10000, 10000),
                'resist_nature'  => valid_int($item['resist_nature'] ?? null, -10000, 10000),
                'resist_holy'    => valid_int($item['resist_holy'] ?? null, -10000, 10000),
                'weight'         => valid_float($item['weight'] ?? null, 0, 10000),
                'description'    => valid_str($item['description'] ?? null, 2000),
                'effects'        => valid_str($item['effects'] ?? null, 4000),
            ]);
            $counts['items']++;
        }
    }

    // --- NPCs (upsert) ---
    if (!empty($data['npcs']) && is_array($data['npcs'])) {
        $npcs = array_slice($data['npcs'], 0, MAX_NPCS);
        $stmt = $db->prepare(
            'INSERT INTO npcs
                (entity_name, entity_type, class_hid, level,
                 max_health, max_mana, is_hostile)
             VALUES
                (:entity_name, :entity_type, :class_hid, :level,
                 :max_health, :max_mana, :is_hostile)
             ON CONFLICT (entity_name, class_hid, level) DO UPDATE SET
                entity_type = COALESCE(EXCLUDED.entity_type, npcs.entity_type),
                max_health = COALESCE(EXCLUDED.max_health, npcs.max_health),
                max_mana = COALESCE(EXCLUDED.max_mana, npcs.max_mana),
                is_hostile = EXCLUDED.is_hostile,
                last_seen = NOW()'
        );

        foreach ($npcs as $npc) {
            if (!is_array($npc)) continue;
            $name = valid_str($npc['entity_name'] ?? null, 128);
            if (!$name) continue;

            $stmt->execute([
                'entity_name' => $name,
                'entity_type' => valid_int($npc['entity_type'] ?? null, 0, 32767),
                'class_hid'   => valid_str($npc['class_hid'] ?? null, 16) ?? '',
                'level'       => valid_int($npc['level'] ?? null, 0, 500),
                'max_health'  => valid_int($npc['max_health'] ?? null, 0, 100_000_000),
                'max_mana'    => valid_int($npc['max_mana'] ?? null, 0, 100_000_000),
                'is_hostile'  => !empty($npc['is_hostile']),
            ]);
            $counts['npcs']++;
        }
    }

    $db->commit();

} catch (Exception $ex) {
    if ($db->inTransaction()) {
        $db->rollBack();
    }
    send_error(500, 'Database error: ' . $ex->getMessage());
}

// Success response
http_response_code(200);
header('Content-Type: application/json');
echo json_encode(['ok' => true, 'inserted' => $counts]);
