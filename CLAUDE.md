# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Quick Reference

```bash
# Run CLI capture tool (requires Administrator terminal on Windows)
python mnm.py

# Run standalone GUI combat parser (requires Administrator)
python parser/parser.py

# Common flags (mnm.py)
python mnm.py --dump-keys              # Read encryption keys from game memory and exit
python mnm.py --log-level DEBUG         # Verbose console output
python mnm.py --no-wait                 # Fail immediately if game not running
python mnm.py -p other.exe -i 10.0.0.5 # Custom process name and interface IP

# Install dependency (only external package)
pip install pycryptodome

# Syntax check after changes
python -c "import core.combat; import core.npc_database; import core.parser"
python -c "import parser.parser"

# Build single-file exe (output: dist/ZekParser.exe)
pyinstaller --onefile --noconsole --name ZekParser --uac-admin --version-file version_info.py --collect-all pycryptodome "parser/parser.py"
```

No test framework exists. Verify changes with `python -c` imports and live capture.

## Two Entry Points

1. **`mnm.py`** — Headless CLI tool. Captures packets, decrypts, logs combat events to console + rotating log files in `logs/`. Records NPC spawns to `data/npc_database.csv`.
2. **`parser/parser.py`** — Standalone tkinter GUI named **ZekParser**. Fully self-contained (zero imports from `core/`). Duplicates the entire capture→decrypt→parse pipeline inline. Shows real-time combat feed + damage meter with DPS tracking. Debug logs go to `parser/logs/`.

Both require Windows Administrator privileges for raw socket capture (`SIO_RCVALL`).

## Architecture

Windows-only network capture tool targeting a Unity MMO (`mnm.exe`) that uses FishNet/LiteNetLib networking. Captures raw packets, decrypts them with keys read from game memory, then parses game-level messages.

### Protocol Stack (outer → inner)

```
Raw Socket (SIO_RCVALL) → IP → UDP/TCP → [CRC32c + AES-256-CBC] → LiteNetLib Frame → Game Messages
```

### Thread Model (5 threads + main)

```
CaptureEngine ──queue──→ PacketProcessor ──→ Console/File loggers
                              ↑ reads                ↓ writes
ConnectionMonitor        CombatParser          NpcDatabase (CSV)
KeyWatcher (memory)
```

- **CaptureEngine** (`core/capture.py`): Raw socket recv loop, pushes to thread-safe queue (max 10k)
- **ConnectionMonitor** (`core/connections.py`): Polls Windows iphlpapi every 5s to track game's TCP/UDP connections. Handles 0.0.0.0 wildcard bindings via port-only matching
- **KeyWatcher** (`core/memory.py`): Reads AES/HMAC/XOR keys from IL2CPP static fields via ReadProcessMemory every 5s
- **PacketProcessor** (`mnm.py`): Main pipeline — parse IP headers, filter by game connections, decrypt, extract LiteNetLib frames, parse game messages, emit combat events, record NPCs
- **Main thread**: Stats logging every 10s, process health monitoring

The standalone GUI (`parser/parser.py`) uses the same thread model with a `CaptureBackend` class that manages lifecycle, connection, key, capture, and processing threads internally, feeding parsed events to the tkinter UI via a thread-safe queue polled with `root.after()`.

### Encryption Pipeline (`core/decrypt.py`)

Wire format: `[IV(16)] [AES-CBC ciphertext(N×16)] [HMAC(32)?] [CRC32c(4)]`

Decryption order: strip CRC from **back** → strip HMAC if key present → AES-256-CBC decrypt (IV = first 16 bytes) → PKCS7 unpad → XOR if key present. Current server only uses AES (HMAC/XOR keys are empty).

Keys live in `Client.ConnectionInfo` static class: `GameAssembly.dll + 0x544FCD8` → Il2CppClass → static_fields → offsets 0x38/0x40/0x48 for HMAC/AES/XOR byte arrays.

### Game Message Format

After LiteNetLib framing, game messages are: `[msg_id (uint16 LE)] [body]`. 355 known message types in `core/opcodes.py`. Strings on wire use LiteNetLib format: `[uint16 LE length] [UTF-8 bytes]` where length includes a trailing null byte.

LiteNetLib PacketProperty byte: bits 0-4 = property type (0=Unreliable, 1=Channeled, 12=Merged are data-bearing), bits 5-6 = connection number, bit 7 = fragmented. Merged packets contain nested LNL sub-frames.

### Key Data Structures

- `ParsedPacket` (`core/parser.py`): IP/transport header fields + raw payload + direction
- `LiteNetLibFrame` (`core/parser.py`): Parsed LNL header with property type, sequence, channel
- `GameMessage` (`core/parser.py`): msg_id + body bytes + msg_name lookup
- `CombatEvent` (`core/combat.py`): Typed event with source/target IDs, fields dict, raw body
- `NpcDatabase` (`core/npc_database.py`): Appends SpawnEntity data to `data/npc_database.csv`

### Configuration

`config.json` at project root. Key fields:

- `player_name`: Leave empty `""` — auto-detected from combat text. Only set manually if auto-detect fails.
- `server_name`: Display label for GUI title bar (e.g. `"Beta PvP"`)
- `process_name`: Target process (default `"mnm.exe"`)
- `interface_ip`: Network interface (`"auto"` for auto-detect, or explicit IP)
- `log_level`: `"DEBUG"`, `"INFO"`, `"WARNING"`, `"ERROR"`
- `capture_filter.protocols`: `["UDP", "TCP"]`
- `capture_filter.exclude_ports`: Ports to ignore (default `[80, 443, 53]`)
- `api_enabled`: `false` to disable API submission
- `api_url`, `api_key`, `api_batch_interval`: Remote API settings for `parser/api_client.py`

## Combat Text Parsing (parser/parser.py)

Combat damage text arrives via two different opcodes:

- **EndCasting (0x0056)**: Carries spell/ability results. Has `entity_id` and `target_id` fields. Format: `[u32 entity_id] [u32 target_id] [string text]`.
- **ChatMessage (0x0040)**: Carries melee auto-attack damage and misc combat text. Channel 1 = combat text. Has **no entity IDs** — attacker/target must be resolved from text. Format: `[u32 channel] [string text] [6 trailing bytes]`.
- **0x644B (Combat Animation)**: Accompanies every melee hit. Has both entity IDs and the verb but **no damage number**. Format: `[AnimEntry attacker] [AnimEntry defender]` where `AnimEntry = [u32 entity_id] [u8 anim_type] [LiteNetLib string verb]`. Types: 0x34=attack, 0x2a=react, 0x00=none. Verbs: "slash"/"stab"/"punch"/"miss" (attack), "ouch" (react). Defender entry is all zeros on misses.

### EndCasting Patterns (6 patterns, checked in order)

1. Third-person spell: `"X's Ability hits Y for N points of Type Damage."` — `^(.+?)'s .+? hits (.+?) for \d+`
2. Local player spell: `"Your Ability hits Y for N points of damage."` — `^Your .+? hits (.+?) for \d+`
3. Local melee + damage: `"You slash Y for N points of damage."` — uses `_MELEE_VERBS` whitelist
4. Third-person melee + damage: `"Bannin slashes Y for N points of damage."` — uses `_MELEE_VERBS(?:e?s)`
5. Local melee, no damage: `"You kick Y."` — uses `_MELEE_VERBS` whitelist
6. Third-person melee, no damage: `"Lilyth kicks Y."` — uses `_MELEE_VERBS(?:e?s)`

Patterns 3-6 use a `_MELEE_VERBS` whitelist (~40 verbs) instead of `\w+` to prevent non-combat verbs like "pulls", "binds", "summons" from corrupting entity names.

### ChatCombat Patterns

ChatCombat first checks for `"for N points of"` as a universal damage indicator (no verb matching needed since the `points of` suffix prevents false positives), then parses structure:

1. Local melee: `"You [verb] [at] X [with offhand] for N ..."`
2. Local ability: `"Your Ability hits X for N ..."`
3. Third-person ability: `"Name's Ability hits X for N ..."`
4. Third-person melee: `"Name [verb]s [at] X [with offhand] for N ..."`

### Entity Resolution for ChatCombat

ChatCombat messages have no entity IDs. Resolution strategy:

1. **Temporal correlation** (`_last_hp_eid`): The target's `UpdateHealth` always arrives right before its `ChatCombat` message. The tracker records the most recent UpdateHealth entity ID and uses it if the name matches (or entity has no name yet) within 2 seconds. This correctly disambiguates when multiple NPCs share the same name.
2. **Name lookup fallback** (`_resolve_target_eid`): Iterates `self.names` looking for a matching name. Prefers alive entities (encounter not dead) over dead ones.
3. **Local player**: Uses `_local_player_eid` (detected from outbound Autoattack/ChangeTarget `entity_id`, or "Your..."/"You..." EndCasting text). If unknown, ChatCombat "You..." damage queues in `_pending_local_dmg` until detection fires.

### Local Player Detection and the `"_local"` Sentinel

Before the local player's entity ID is known, autoattack/target tracking uses the string `"_local"` as a placeholder in `_autoattack_on`, `autoattack_target`, and `last_attacker`. Three detection paths set `_local_player_eid`:

1. **Autoattack OUT** / **ChangeTarget OUT**: Outbound packets carry the local player's `entity_id` — `_mark_local_player(eid)` is called immediately. This is the primary detection path and works for pure melee players.
2. **EndCasting text**: "Your Ability hits..." / "You slash..." patterns call `_mark_local_player(eid)`.
3. **Heal text**: "heals you" EndCasting calls `_mark_local_player(target_id)`.

When `_mark_local_player` fires, it retroactively merges all `"_local"` sentinel entries:
- Replaces `"_local"` → real eid in `last_attacker` dict
- Merges `damage_dealt`, `first_dealt`, `last_dealt` from key `"_local"` into the real eid
- Merges `"_local"` encounter player entries (dealt, text_dealt, received, abilities) into real eid entries
- Flushes `_pending_local_dmg` queue

In UpdateHealth processing, any remaining `"_local"` in `last_attacker` is resolved to `_local_player_eid` as a safety net.

## Encounter System (parser/parser.py)

`EntityTracker` maintains per-entity encounter records via `Encounter` objects keyed by entity ID in `_encounter_map`:

- **`total_damage`**: Sum of HP deltas from `UpdateHealth` messages (can be percentage-based for tough NPCs with max_hp=100)
- **`text_damage`**: Sum of damage numbers extracted from combat text (always real damage values)
- **`best_damage`**: `max(text_damage, total_damage)` — displayed in the UI
- **`players`** dict: Per-attacker breakdown with `dealt` (HP-based) and `text_dealt` (text-based)

### NPC Encounters

Created when `entity_type != 0` (NPC or unknown). Entities with unknown type (no SpawnEntity captured) are assumed NPC — this can cause false encounters for other players whose spawn wasn't captured.

SpawnEntity messages only retire an existing encounter from `_encounter_map` if the entity **name has changed** (real eid reuse by a different mob). Repeated SpawnEntity for the same entity (pets, mobs moving in/out of view range) preserves the encounter mapping.

### PvP Encounters

Created when both target and attacker are `entity_type == 0` (both players). PvP encounters appear in the encounter list alongside NPC encounters and support the same detail view with per-player damage breakdown.

The PvP system gates text damage resolution on encounter existence: `_resolve_target_eid`, the ChatCombat HP-correlation path, and the `_pending_chat_dmg` flush all allow player targets **only if** a PvP encounter already exists in `_encounter_map`. This prevents ambient player HP updates from creating ghost PvP encounters — the encounter must first be established by a confirmed player-on-player `UpdateHealth` damage event (logged as `ENC_PVP`).

## Item Tracker (parser/parser.py)

The left panel toggles between combat feed and item tracker via the "Items" button. Three view states: `"feed"`, `"items"`, `"item_detail"`.

- **Data**: `CaptureBackend` stores `_items` (hid → full ItemRecord dict) and `_item_drops` (list of `{hid, name, quantity, timestamp, npc_name}`). Thread-safe via `_item_lock`.
- **Item list**: Clickable rows showing item name, count, and compact stats preview (DMG/AC/primary stats). Sorted by drop count descending.
- **Item detail**: Full stats view — HID, type/slot/level, flags (MAGIC/NO DROP/UNIQUE), damage/AC, primary stats, HP/mana/regen, haste, resists, weight, description, effects, and last 10 drop timestamps with NPC source names.
- **Refresh**: 1-second polling with fingerprint-based skip-redraw optimization (same pattern as encounter meter).
- **Loot context**: `_last_loot_target` maps entity ID → NPC name so items can be associated with the mob that dropped them.

Items are also queued to the API client when `api_enabled` is true.

## API Client (parser/api_client.py)

`ApiClient` runs a background thread that batches and sends data to a remote API every N seconds (default 15). Imported only by `parser/parser.py`, not `core/`.

- **Queues**: `queue_combat_event()`, `queue_loot_event()`, `queue_item()` (deduped by HID), `queue_npc()` (deduped by name+class+level)
- **Auth**: HMAC-SHA256 signing with `X-API-Key`, `X-API-Timestamp`, `X-API-Signature` headers
- **Config**: `api_enabled`, `api_url`, `api_key`, `api_batch_interval` in `config.json`
- **Retry**: 3 attempts with exponential backoff, skips on auth errors

## IL2CPP Memory Layout

byte[] in memory: `[klass(8)] [monitor(8)] [bounds(8)] [length(4)] [pad(4)] [data...]` — array data at offset 0x20, length at 0x18. Il2CppClass static_fields pointer is at class+0xB8. Class name char* at class+0x10.

## SpawnEntity Parsing

`_parse_spawn_entity()` in `core/combat.py` uses **phased parsing with fallback**. The HID string fields (classHID, raceHID, sexHID) between name and health don't follow standard LiteNetLib uint16-len string format for NPCs — the sexHID offset reads as uint16 LE = 1024 which is invalid. The parser:

1. Tries sequential string reads for the HID section
2. On failure, scans ahead for the health/maxHealth stats block (`_find_stats_offset()` looks for two plausible consecutive int32 values)
3. Extracts class/sex codes from the raw HID region bytes via ASCII scanning (`_parse_hid_region()`)
4. Continues parsing stats, position, booleans, model data, and appearance arrays from the found offset

Each phase (identity, HID, stats, position, booleans, model, appearance) has independent error recovery so a failure in one section doesn't blank out later fields.

**Standalone parser note**: `parser/parser.py` has its own SpawnEntity parser with the same phased approach. Spawn HP from `_find_stats()` is unreliable (often misaligned, producing garbage like 3072/49920) — the standalone parser does NOT use spawn HP as the damage baseline. Instead, the first `UpdateHealth` message sets the real HP baseline.

## Build & Distribution (ZekParser.exe)

PyInstaller single-file build with `--noconsole` (no console window), `--uac-admin` (proper UAC elevation prompt), and `version_info.py` (embeds product metadata to reduce AV false positives). The exe is unsigned — tell users to add a Defender exclusion for `ZekParser.exe` or its folder.

### Debug Logging

`_setup_parser_log()` checks `getattr(sys, 'frozen', False)`:
- **`python parser/parser.py`** (dev): Full DEBUG logging to `parser/logs/parser_<timestamp>.log` (10MB rotating, 3 backups). All `_plog.debug(...)` calls active — covers damage attribution, encounter creation, entity resolution, ChatCombat parsing.
- **Frozen exe**: `NullHandler` + `CRITICAL` level — zero logging overhead.

### Crash Handling

The exe uses `--noconsole` so `print()`/`input()` do nothing. Crashes show a native Windows `MessageBoxW` with the traceback, and write `crash.log` next to the exe (via `_crash_log_dir()` which uses `os.path.dirname(sys.executable)` for frozen builds, not `__file__` which points to the PyInstaller temp dir). The admin check also uses a message box instead of printing.

## Important Gotchas

- CRC32c is at the **back** of the packet, not front
- AES is CBC mode with per-packet IV (first 16 bytes), not ECB
- .NET Aes defaults to PKCS7 padding — must unpad after decrypt
- TypeInfo RVA `88407256` decimal = `0x544FCD8` hex (previous wrong conversion caused key read failures)
- Game binds UDP to 0.0.0.0 — connection matching must use port-only fallback
- Logger must have `logger.setLevel(DEBUG)` set on the logger itself; handler-level filtering alone is insufficient
- `read_string()` strips trailing null byte since LiteNetLib includes it in the length count
- Console output strips BEL characters (`\x07`) to prevent Windows terminal beeping on decoded packet data
- Spawn packet HP values from `_find_stats()` scan are frequently wrong (misaligned byte reads produce multiples of 256) — never trust them as damage baselines
- `parser/parser.py` is intentionally self-contained with duplicated logic from `core/` — do not add imports from `core/`
- Melee auto-attack damage text ("You slash X for N damage") is in **ChatMessage (0x0040) channel 1**, NOT EndCasting (0x0056). Each melee hit sends 3 messages: `UpdateHealth` + `ChatMessage` + `0x644B` (animation). The 0x644B has both entity IDs and the verb but NOT the damage number — the damage value only exists in the ChatMessage English text
- ChatCombat messages have **no entity IDs** — target must be resolved by temporal correlation with the preceding `UpdateHealth`, not by name lookup (multiple NPCs share names)
- EndCasting text for non-combat actions ("Rainbow pulls you through a shimmering portal") will match broad verb patterns — use the `_MELEE_VERBS` whitelist, not `\w+`
- `config.json` `player_name` should be empty string `""` — the parser auto-detects it from outbound Autoattack/ChangeTarget packets and "Your..."/"You..." combat text patterns
- Never use `"_local"` string as a real entity ID — it's a sentinel placeholder for the local player before detection. Always resolve via `_local_player_eid` at consumption points and merge in `_mark_local_player`

## Networking Assessment: Combat Packets (Suggestions for Game Dev Team)

This section documents protocol-level observations from reverse-engineering the combat packet flow. The focus is scalability, bandwidth efficiency, and design oddities that would cause problems as player count grows.

### 1. Damage Delivered as Human-Readable Chat Strings (Critical)

Melee auto-attack damage is not sent as a structured message. Instead, the server composes an English sentence like `"You slash a dunes madman for 52 points of damage."` and sends it inside `ChatMessage (0x0040)` on channel 1. This is the **only** way the client learns the melee damage amount.

There is no structured damage opcode anywhere in the combat packet flow. The companion `0x644B` animation message (see below) carries `attacker_eid`, `target_eid`, and the verb string ("slash", "punch", "stab") — but **not the damage number**. The damage value exists only in the English chat string.

**Why this is a problem:**
- A structured melee damage message would be ~14 bytes: `[u16 msg_id][u32 attacker][u32 target][u16 amount][u8 type]`. The equivalent chat string is 40-80+ bytes of UTF-8 text, 3-6x the size.
- The ChatMessage carries **no entity IDs**. The client (or any parser) must regex-match the English text to figure out who hit whom. The 0x644B animation message has the entity IDs but not the damage. The information is split across two messages where one would suffice.
- If the game is ever localized to another language, every client-side parser breaks.
- In a 50-player raid where 20 melee attackers each swing once per second, that's 20 chat strings/sec (~1.2 KB/s) broadcast to all nearby players instead of 20 structured messages (~280 bytes/s). The bandwidth gap widens with player count.

**Suggested fix:** Add a `damage_amount` field to the `0x644B` animation message (which already has both entity IDs and the verb), or create a dedicated `MeleeDamage` opcode: `[u32 attacker_eid] [u32 target_eid] [u16 damage] [u8 damage_type] [u8 verb_id]`. Either way, the ChatMessage text can then be composed client-side.

### 2. Duplicate Damage Reporting (UpdateHealth + Text)

Every single combat hit sends **both** an `UpdateHealth` message (with the new HP value) **and** a separate damage text message (EndCasting or ChatMessage). The damage number exists in two places on the wire for every hit.

Worse, for tough NPCs, `UpdateHealth` reports **percentage-based HP** (max_hp=100) while the text message carries the **real damage number** (e.g. "252 points of Fire Damage"). These two systems disagree, forcing the client to maintain two parallel damage tracking systems and pick the higher one.

**Suggested fix:** Either include the raw damage amount as a field in `UpdateHealth`: `[u32 eid] [i32 new_hp] [i32 max_hp] [u16 damage_dealt] [u32 attacker_eid]`, or ensure `UpdateHealth` always sends real HP values (not percentages). Eliminate the need for clients to cross-reference two different messages to figure out the actual damage.

### 3. EndCasting Overloaded as Combat Log + Narrative Channel

`EndCasting (0x0056)` carries everything from spell damage (`"Your Fireball hits X for 200 points of Fire Damage."`) to world flavor text (`"Rainbow pulls you through a shimmering portal."`), crafting results, and buff notifications — all as freeform English strings. There is no type field to distinguish combat from non-combat text.

**Why this is a problem:**
- The client must pattern-match every EndCasting string against 6+ regex patterns just to determine if damage happened. A non-combat sentence with a coincidentally matching structure creates ghost damage events.
- The `entity_id` field in EndCasting sometimes points to the caster and sometimes to the player, with no flag indicating which. For melee EndCasting, `target_id` often points to the **player** (entity_type=0) rather than the NPC being hit, making the target ID unreliable.
- Adding new spell text formats requires updating every client-side parser.

**Suggested fix:** Split EndCasting into typed sub-messages or add a `result_type` enum field: `0=damage, 1=heal, 2=resist, 3=flavor_text, 4=craft_result`. Include `damage_amount`, `damage_type`, and `heal_amount` as structured fields so clients don't need to parse English.

### 4. SpawnEntity is a Variable-Length Parsing Nightmare

`SpawnEntity (0x0020)` is a large, variable-length message with no length-prefixed sections or field count. The HID string fields (classHID, raceHID, sexHID) between the entity name and health stats **don't follow the standard LiteNetLib string format** for NPCs — the sexHID field reads as uint16 LE = 1024, which is an obviously invalid string length. This forces parsers to abandon sequential reading and **brute-force scan** for the health stats block by looking for two plausible consecutive int32 values.

**Specific issues:**
- Player SpawnEntity and NPC SpawnEntity use different byte layouts for the same opcode with no type flag to distinguish them up front (entity_type comes first, but the HID section layout varies unpredictably).
- Stats (HP/MP), position (XYZ floats), booleans, model data, and appearance arrays are all packed sequentially with no section headers, so a single off-by-one in any section corrupts everything downstream.
- HP values from SpawnEntity are frequently wrong (misaligned reads produce values like 3072/49920), making them unusable as damage baselines.

**Suggested fix:** Use a TLV (type-length-value) or protobuf-style encoding for SpawnEntity. At minimum, add a `u16 field_count` or `u16 section_offset` table at the start so parsers can skip to the section they need. Ensure NPC and player spawns either use the same field layout or are split into separate opcodes.

### 5. No Attacker ID on UpdateHealth

`UpdateHealth (0x0022)` is `[u32 entity_id] [i32 new_hp] [i32 max_hp]` — 12 bytes total. It tells you **who lost health** and **how much**, but not **who caused it**. The client must correlate damage attribution from separate `BeginCasting` / `EndCasting` / `ChatMessage` events that may arrive before or after the UpdateHealth, depending on server processing order.

**Why this is a problem at scale:**
- When multiple players attack the same NPC simultaneously, the client receives interleaved `BeginCasting` from player A, `UpdateHealth` from NPC, `BeginCasting` from player B, `UpdateHealth` from NPC — and must maintain a stateful attacker-attribution model to figure out which HP drop corresponds to which attacker.
- Damage Shield effects reverse the expected packet order: UpdateHealth for the **player** (reflecting damage) arrives before UpdateHealth for the NPC, breaking temporal correlation assumptions.
- In a group fight, dropped or out-of-order UDP packets make attribution impossible to reconstruct.

**Suggested fix:** Add `[u32 source_eid]` and `[u16 ability_id]` to UpdateHealth. One message, all the information, no cross-referencing needed.

### 6. Per-Packet AES-256-CBC Encryption Overhead

Every UDP datagram is encrypted with AES-256-CBC using a per-packet random IV. The encryption envelope adds 20 bytes minimum per packet: `[IV(16)] + [CRC32c(4)]`, plus PKCS7 padding rounds the ciphertext up to the next 16-byte block.

**Cost for combat traffic:**
- An `UpdateHealth` message is 12 bytes of game data + 2 bytes msg_id + 4 bytes LNL header = ~18 bytes payload. After AES-CBC: 16 (IV) + 32 (2 AES blocks with padding) + 4 (CRC) = 52 bytes. The encryption envelope is **2.9x the payload size**.
- In a 40-player raid with 10 mobs, a busy combat second might produce 50+ UpdateHealth messages. The encryption overhead alone adds ~1.7 KB/s of pure waste per client.
- The CRC32c provides integrity checking, but AES-CBC already provides authenticated encryption if paired with HMAC (which the protocol supports but currently leaves empty). Running CRC32c on top of AES-CBC is redundant if HMAC is enabled.

**Suggested fix:** Consider AES-GCM (authenticated encryption, no separate HMAC or CRC needed). For combat-heavy traffic, consider batching: collect all combat events from a single server tick into one encrypted payload instead of encrypting each individually. One IV + one CRC for 10 messages instead of 10 of each.

### 7. Merged Packets Don't Batch by Purpose

LiteNetLib's Merged packet type (property 12) batches multiple sub-messages into one UDP datagram — which is good. However, the batching appears to be purely opportunistic (whatever is in the send queue), not organized by message type or priority.

**Combat implication:** A time-critical `UpdateHealth` message can be bundled with a `PositionUpdateNew` for an entity 500 meters away and a `RemoveBuffIcon` for an expired buff. The client must deserialize the entire merged payload before it can process the HP update. In a high-load scenario where the server merges 15+ sub-messages per datagram, combat responsiveness depends on how fast the client can iterate through unrelated messages to find the ones that matter.

**Suggested fix:** Priority-based batching — group combat-critical messages (UpdateHealth, Die, BeginCasting) separately from world-state messages (position updates, buff icons). This allows the client to process combat updates with lower latency.

### 8. Entity IDs are 32-bit with No Namespacing

Entity IDs are `uint32` allocated presumably by the server. When entities despawn and new ones spawn, IDs can be reused. There's no generation counter or epoch to distinguish "entity #17977 the first dunes madman" from "entity #17977 the second dunes madman that spawned 5 minutes later."

**Combat implication:** If a parser or client caches any state by entity ID (HP baselines, encounter records, attacker attribution), a reused ID silently corrupts that state. The parser has to manually detect ID reuse via SpawnEntity and retire old records, which is fragile.

**Suggested fix:** Either use 64-bit entity IDs with a monotonic counter (never reuse), or add a `u16 generation` field to entity-bearing messages so clients can detect stale references.

### 9. Three Separate Opcodes for Resource Updates

Health, mana, and endurance each have their own opcode: `UpdateHealth (0x0022)`, `UpdateMana (0x0023)`, `UpdateHealthMana (0x0027)`, `UpdateEndurance (0x022F)`. When a player gets hit and loses both HP and mana (e.g. mana burn), the server sends two separate messages instead of one.

There's also `UpdateHealthMana` which combines HP and mana into one message — but it's used inconsistently. Sometimes the server sends `UpdateHealth` + `UpdateMana` separately for the same tick, sometimes `UpdateHealthMana`.

**Suggested fix:** Single `UpdateResources` opcode with a bitmask indicating which fields are present: `[u32 eid] [u8 field_mask] [i32 hp?] [i32 max_hp?] [i32 mp?] [i32 max_mp?] [i32 end?] [i32 max_end?]`. One message, one encryption, one LNL frame.

### 10. Summary — Bandwidth Cost Per Melee Hit

A single melee auto-attack currently generates **3 messages** on the wire:

| Message | Game payload | Encrypted wire size |
|---|---|---|
| UpdateHealth | ~14 bytes | ~52 bytes |
| ChatMessage (damage text) | ~60 bytes | ~100 bytes |
| 0x644B (animation: verb + entity IDs, NO damage) | ~23 bytes | ~56 bytes |
| **Total** | **~94 bytes** | **~208 bytes** |

A single structured `MeleeDamage` + `UpdateHealth` approach could deliver the same information in 2 messages totaling ~30 bytes of game payload / ~84 bytes encrypted. That's a **60% bandwidth reduction per melee swing** — significant when multiplied across dozens of players in combat.
