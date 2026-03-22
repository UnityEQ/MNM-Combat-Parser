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

# Install dependencies
pip install pycryptodome
pip install chime

# Syntax check after changes
python -c "import core.combat; import core.npc_database; import core.parser"
python -c "import parser.parser"
python -c "import chatparser.bot"

# Build ZekParser exe (output: dist/ZekParser.exe)
pyinstaller --onefile --noconsole --name ZekParser --uac-admin --version-file version_info.py --collect-all pycryptodome "parser/parser.py"

# Build ChatParser exe (output: dist/ChatParser.exe)
pyinstaller --clean ChatParser.spec
```

No test framework exists. Verify changes with `python -c` imports and live capture.

## Three Entry Points

1. **`mnm.py`** — Headless CLI tool. Captures packets, decrypts, logs combat events to console + rotating log files in `logs/`. Records NPC spawns to `data/npc_database.csv`.
2. **`parser/parser.py`** — Standalone tkinter GUI named **ZekParser** (window title: `"ZekParser {APP_VERSION}"`). Fully self-contained (zero imports from `core/`). Duplicates the entire capture→decrypt→parse pipeline inline. Shows real-time combat feed + damage meter with DPS tracking. Debug logs go to `parser/logs/`. `APP_VERSION` constant (e.g. `"V1.16"`) at top of file — bump for each exe release. Keep in sync with `version_info.py` (`filevers`/`prodvers`/`FileVersion`/`ProductVersion`) and `zekparser-homepage/index.html`.
3. **`chatparser/bot.py`** — Standalone tkinter GUI named **ChatParser** (window title: `"ChatParser V{version}"`). Fully self-contained (zero imports from `core/` or `parser/`). Duplicates the capture→decrypt→parse pipeline. Provides text trigger matching with keyboard automation, opcode browser, entity discovery with alerts, and chime sound library. Version in window title (e.g. `"ChatParser V2.6"`) — keep in sync with `chatparser/version_info.py` and `zekparser-homepage/chatparser.html`.

All three require Windows Administrator privileges for raw socket capture (`SIO_RCVALL`).

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

Keys live in `Client.ConnectionInfo` static class: `GameAssembly.dll + 0x544FCD8` → Il2CppClass → static_fields → offsets 0x38/0x40/0x48 for HMAC/AES/XOR byte arrays. The RVA (0x544FCD8) is cached in `rva_cache.json` next to the exe/script — `_load_rva()` reads it on startup, `_save_rva()` writes newly discovered RVAs from `_scan_for_class()`. If the cached RVA fails (game update), the scanner brute-forces the module and saves the new offset.

### Game Message Format

After LiteNetLib framing, game messages are: `[msg_id (uint16 LE)] [body]`. 407 known message types in `core/opcodes.py`. Strings on wire use LiteNetLib format: `[uint16 LE length] [UTF-8 bytes]` where length includes a trailing null byte.

LiteNetLib PacketProperty byte: bits 0-4 = property type (0=Unreliable, 1=Channeled, 12=Merged are data-bearing), bits 5-6 = connection number, bit 7 = fragmented. Merged packets contain nested LNL sub-frames.

### Key Data Structures

- `ParsedPacket` (`core/parser.py`): IP/transport header fields + raw payload + direction
- `LiteNetLibFrame` (`core/parser.py`): Parsed LNL header with property type, sequence, channel
- `GameMessage` (`core/parser.py`): msg_id + body bytes + msg_name lookup
- `CombatEvent` (`core/combat.py`): Typed event with source/target IDs, fields dict, raw body
- `NpcDatabase` (`core/npc_database.py`): Appends SpawnEntity data to `data/npc_database.csv`. Deduplicates on `(entity_id, name)` tuple — same eid with different names gets recorded twice (eid reuse by different mobs).

### Supporting Modules

- **`core/logger.py`**: Dual-output logging — colored ANSI console (with Windows support) + rotating file. `PacketAdapter` adds direction tags. Strips BEL characters (`\x07`) from console output.
- **`core/process.py`**: Process discovery via `CreateToolhelp32Snapshot`. Multi-instance selection prompt, process health checking, wait-for-process polling.

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

### `_mark_local_player` Guard

`_mark_local_player(eid)` **rejects** different eids once `_local_player_eid` is set — prevents NPC eids from overwriting the real local player. Only allows re-marking the same eid (for name refresh). The "YOU" fallback name is replaced when a real name becomes available.

### ClientPartyUpdate (0x0380)

Sent when a player does `/reload` in-game. Provides class/level/zone for all party members. Wire format:

```
[u32 member_count]
per member: [u32 entity_id] [u32 unknown] [LNL string name] [u8 0x00] [3 raw ASCII class_hid] [u8 level] [LNL string zone_hid]
[u32 leader_eid]
```

The class field is NOT a LNL string — it's 3 raw ASCII lowercase bytes (e.g. `70 61 6c` = "pal") preceded by a `0x00` separator byte. The level is a single u8 immediately after. This was previously misread by `_scan_class_hid()` ASCII scanning which would include the level byte in the class string when level >= 32 (0x20 = space, in printable ASCII range).

**Offline members** (eid=0) use a shorter format with NO zone LNL string: `[u32 eid=0] [u32 cid] [LNL name] [u8 0x00] [3 bytes class=0x000000] [u8 level=0]`. The parser detects this via `eid==0 AND class_bytes==\x00\x00\x00 AND level==0` and skips the zone read to keep offsets aligned.

Handler sets `entity_types[eid] = 0` for all online members, populates `classes`/`levels`/`names`, calls `_backfill_player_info()` to retroactively update encounter records.

**Zone change eid migration**: `_party_eids` dict tracks `name → current_eid`. When ClientPartyUpdate arrives with a known name but different eid (all eids change on zone), the handler clears the old eid's `entity_type` and carries over class/level/zone to the new eid. If the local player's eid changed, it clears `_local_player_eid` and re-marks via `_mark_local_player(new_eid)`.

### /reload Gate System

`_reload_gate` flag (default `True`) blocks ALL event processing in `EntityTracker.process()` except ClientPartyUpdate. This prevents misidentification of the local player from early combat text (e.g. "Poacher Garrus" NPC being set as player name).

When ClientPartyUpdate arrives:
- **Solo** (1 valid member): auto-detects local player, clears gate immediately
- **Group** (>1 valid members): stores `_party_members_pending` list, GUI shows player selection buttons ("which one is you?")
- **No valid members**: gate clears anyway (prevents permanent lockout)

The GUI displays a full-screen overlay ("Type /reload in-game to start") while the gate is active. The overlay is destroyed in `_poll_queue()` when `_reload_gate` becomes False.

## Entity Type System (parser/parser.py)

- `entity_types` dict: `eid → entity_type` (uint16 from SpawnEntity). `0` = player, `> 0` = NPC/pet, `None` = unknown (no SpawnEntity captured).
- `pet_states` dict: `eid → True` if SpawnEntity tail marker == 5 (pet/charmed NPC).
- `_pet_owners` dict: `pet_eid → owner_eid` from SpawnEntity parentID field at `body[len-93]`.
- `_looks_like_npc_name(name)`: Returns `True` if name starts lowercase (e.g. "a bodyguard") or is "Entity#...". Used as heuristic to filter unknown entities.
- Party members get `entity_types[eid] = 0` from `ClientPartyUpdate`.
- Local player gets `entity_types[eid] = 0` from `_mark_local_player()`.

### Overview Filtering

The overview uses strict type checking — only confirmed players and pets appear. Inclusion rules:
- `entity_type == 0` → always included (confirmed player)
- `eid == _local_player_eid` → always included (local player)
- `entity_type > 0` and `pet_states[eid] == True` → included; damage merged into owner's row as `[PET] PetName` ability entry
- `entity_type > 0` and not pet → excluded (regular NPC)
- `entity_type is None` (unknown) → excluded (not a confirmed player)

### Pet Detection from SpawnEntity

SpawnEntity body tail marker (last u16) identifies entity type: 0=player/object, 1=regular NPC, 5=pet, large value=player with gear data. When `last_u16 == 5`, the parser reads `parent_id` (owner eid) at `body[len-93]`. Pet damage in the overview is merged into the owner's ability breakdown as a `[PET] PetName` entry. Pets without a known owner (no SpawnEntity captured) still appear as separate `[PET]` rows.

This strict filter replaced an earlier heuristic-based system that leaked uppercase-named NPCs (e.g. "Poacher Garrus") into the overview.

### Class HID Mapping

`CLASS_HID_NAMES` dict maps 3-letter codes from SpawnEntity/ClientPartyUpdate to class names (e.g. `"dru"→"Druid"`, `"pal"→"Paladin"`, `"war"→"Warrior"`). `_class_label(hid)` returns the full name; unknown codes pass through as-is. `_scan_class_hid(hid_region)` extracts class codes from SpawnEntity HID region via ASCII byte scanning when standard string parsing fails.

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

## GUI Layout (parser/parser.py)

### Window Sizing (1080p optimized)

- Default (left panel collapsed): `425x300`, minsize `350x220`
- Expanded (both panels): `850x300`, minsize `600x220`
- Left panel starts hidden — user clicks expand arrow to show it

### Left Panel Views

Dropdown (`_left_combo`) switches between views. `_left_view` state values:

| Dropdown Label | `_left_view` value | Description |
|---|---|---|
| Feed | `"feed"` | Real-time scrolling combat log, color-coded by event type |
| Items | `"items"` | Clickable item drop list with stats preview |
| (item click) | `"item_detail"` | Full item stats, effects, drop history |
| Triggers | `"triggers"` | User-defined text pattern matching with audio alerts (`triggers.json`) |
| Experience | `"experience"` | XP gain tracking per kill with session summary |

Copy button copies text from whichever view is active. Export button exports to CSV.

### Right Panel Views

Dropdown (`_meter_combo`) switches between views. `_meter_view` state values:

| Dropdown Label | `_meter_view` value | Description |
|---|---|---|
| Overview | `"overview"` | Session leaderboard — top players ranked by total damage with expandable ability breakdown |
| Encounters | `"encounters"` | Live/dead NPC encounter list sorted by recency |
| (encounter click) | `"encounter_detail"` | Per-player damage breakdown for one encounter |
| Grand Overview | `"grand_overview"` | Aggregated stats across all encounters |

Overview uses in-place button label updates via `_overview_structure` tracking (prevents flicker). Full redraw only on structural change (new player, expand/collapse, rank reorder). `_overview_expanded` set tracks which players have ability breakdowns expanded.

## Item Tracker (parser/parser.py)

- **Data**: `CaptureBackend` stores `_items` (hid → full ItemRecord dict) and `_item_drops` (list of `{hid, name, quantity, timestamp, npc_name}`). Thread-safe via `_item_lock`.
- **Item list**: Clickable rows showing item name, count, and compact stats preview (DMG/AC/primary stats). Sorted by drop count descending.
- **Item detail**: Full stats view — HID, type/slot/level, flags (MAGIC/NO DROP/UNIQUE), damage/AC, primary stats, HP/mana/regen, haste, resists, weight, description, effects, and last 10 drop timestamps with NPC source names.
- **Refresh**: 1-second polling with fingerprint-based skip-redraw optimization (same pattern as encounter meter).
- **Loot context**: `_last_loot_target` maps entity ID → NPC name so items can be associated with the mob that dropped them.

Items are also queued to the API client when `api_enabled` is true.

## Experience Tracking (parser/parser.py)

`UpdateExperience (0x0024)`: `[u32 entity_id] [u32 experience]` — XP value is **per-level progress** (not lifetime total). Resets to near-zero on level-up.

- **State**: `_xp_current` (eid → last XP), `_xp_events` (list of gain records), `_xp_level_start` (eid → XP at level start), `_xp_level_needed` (eid → XP cap for level), `_xp_player_level` (eid → level)
- **First event baseline**: First `UpdateExperience` in a session silently records the XP value and returns `None` — no event shown. Second kill onwards computes proper deltas.
- **Level-up detection**: When `new_xp < prev_xp`, the player leveled up. The old value becomes the level cap (`_xp_level_needed`). XP percentage is computed from this.
- **NPC correlation**: Each UpdateExperience resolves the NPC via `_last_hp_eid` (most recent UpdateHealth entity) or dead encounter fallback. The resolved NPC name is attributed directly to the current XP delta.
- **Display**: Summary shows total gained + kill count + XP/hour. Event rows show timestamp, `+N XP`, percentage if known, and mob name.

## Trigger System (parser/parser.py)

User-defined text pattern alerts stored in `parser/triggers.json` (ships empty `[]`).

- **Matching**: Case-insensitive substring match against every combat text message (EndCasting, ChatCombat, Die, etc.). `_trigger_counts` tracks match counts per pattern.
- **Sound**: Queued to `_trigger_sound_queue` (thread-safe), drained on GUI thread every 500ms via `winsound.PlaySound(SND_ASYNC)`. 10 built-in Windows system sounds available.
- **UI**: Pattern entry + sound dropdown + preview button. Shows live match counts per trigger.

## Rendering Optimization (parser/parser.py)

All panel views use **fingerprint-based skip-redraw**: `_meter_build_fingerprint()` builds a hashable tuple of current state. If unchanged from last render, the 1-second refresh cycle skips the view entirely.

Within the overview, a two-tier system prevents flicker:
1. **Fingerprint** (encounter-level totals) gates whether `_render_overview()` is called at all
2. **Structure key** (`_overview_structure`) tracks player order + expanded state + ability data. If structure matches, only player summary lines are updated in-place via `tag_ranges()`. Structure mismatch triggers full redraw.

The structure key includes ability `(name, damage)` tuples for expanded players, so real-time damage changes to abilities trigger a full redraw when expanded.

Encounter list uses the same pattern: `_enc_list_structure` tracks button eid sequence, in-place label updates when structure matches.

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

## ChatParser (chatparser/bot.py)

Standalone tkinter GUI for chat trigger matching, keyboard automation, opcode inspection, and entity discovery. Fully self-contained — zero imports from `core/` or `parser/`. Duplicates the capture→decrypt→parse pipeline inline, same as `parser/parser.py`.

### GUI Layout

- Window: `620x900px`, always-on-top, 75% opacity (semi-transparent overlay)
- Three sections stacked vertically: Connection Status, Trigger/Opcode/Discovery area, Run Log
- Three sub-tabs in the middle section: **Main** (text triggers), **Opcode Browser** (raw message inspection), **Discovery** (NPC/PC name tracking)

### Trigger System

Triggers are user-defined pattern matchers stored in `chatparser/triggers.json`. The file uses a dict format: `{"triggers": [...], "discovery_alerts": [...]}`. Backward compatible — if file contains a flat list (old format), it's treated as `{"triggers": list, "discovery_alerts": []}`. Each trigger has:

- **Pattern**: Case-insensitive substring match against combat/chat text
- **Mode**: `"loop"` (repeat key presses), `"once"` (single key press cycle), `"sound"` (audio alert only)
- **Key pairs**: `[{"key": "4", "wait": "1"}, ...]` — keys to press with wait times in seconds
- **Sound**: From `ALERT_SOUNDS` list — chime library sounds (`"chime:theme:type"` format, 7 themes × 4 types = 28 sounds). `_play_sound()` detects the `"chime:"` prefix and calls the chime library; requires `pip install chime`.
- **Auto-target**: Extract speaker name from matched text for `/target` automation
- **Cooldown**: Automatic per-trigger cooldown = `sum(key wait times) + 1s buffer`

Two trigger types:
- **Text triggers**: Match against ChatMessage/EndCasting/Die text
- **Opcode triggers**: Match a specific field value in a specific opcode (e.g. `0x0020.name = "Poacher"`)

### Opcode Browser

Live message inspector with filter categories (Chat, Combat, All), search, and per-category ring buffers (Chat: 2000, Combat: 2000, All: 5000). Click any message for a detail view showing parsed fields + raw hex dump. Can create opcode triggers directly from the detail view.

### Discovery Tab

Two-column display tracking unique NPC and PC names from SpawnEntity (0x0020). `entity_type != 0` = NPC, `entity_type == 0` = PC. Copy button exports both lists, Reset clears them. Data tracked via `MessageHandler._npc_names` and `._pc_names` dicts with version counter for efficient UI cache invalidation.

**Discovery Alerts**: Collapsible panel at top of Discovery tab. Users add patterns (case-insensitive substring match) that trigger a chime sound + yellow highlight when matching entity names spawn. Each alert has NPC/PC toggle buttons and a sound dropdown. Alerts stored in `triggers.json` under `"discovery_alerts"` key. `_disc_alerted_names` set prevents repeat alerts within a session (cleared on Reset). Alert rows live in a scrollable canvas capped at 120px.

### MessageHandler

Parses a subset of opcodes for trigger matching and display: SpawnEntity (0x0020), ChatMessage (0x0040), EndCasting (0x0056), Die (0x0013), UpdateHealth (0x0022), UpdateHealthMana (0x0027), UpdateExperience (0x0024), BeginCasting (0x0055), DespawnEntity (0x0021). Maintains `_names` dict (`eid → name`) for entity resolution. Thread-safe via `_lock`.

### Bot Thread

When bot is ON and a trigger fires, a background thread executes key presses via `SendInput` (Windows API). Key pairs are processed sequentially with configurable waits. Loop mode repeats the full cycle `loop_count` times with `loop_delay` between cycles.

### Version Management (ChatParser)

- `chatparser/bot.py` line with `self.title("ChatParser V{version}")` — window title
- `chatparser/version_info.py` — exe file metadata (`filevers`/`prodvers`/`FileVersion`/`ProductVersion`)
- `zekparser-homepage/chatparser.html` — download page (`softwareVersion` schema + CTA button)
- **All three must be kept in sync** when bumping versions

### Build (ChatParser.exe)

Uses `ChatParser.spec` at project root: `pyinstaller --clean ChatParser.spec`. Output: `dist/ChatParser.exe`. The spec references `chatparser/version_info.py` for embedded version metadata, `chatparser/bot.py` as entry point, `--noconsole`, `--uac-admin`, `upx=True`. The spec also bundles chime's `themes/` WAV directory via explicit datas entry.

### Auto-Updater (both exes)

Both `parser/parser.py` and `chatparser/bot.py` have `_check_for_update()` that runs on startup (frozen exe only). Downloads the exe from `zekparser.com`, compares SHA-256 hashes, and if different: writes `.new` file, renames running exe to `.old`, renames `.new` to exe name, restarts. Key details:
- Must use a custom `User-Agent` header — server 403s the default `Python-urllib` agent
- No HEAD requests — server 403s those too
- SSL uses `_create_unverified_context()` (PyInstaller bundles lack CA certs)
- All errors silently caught to avoid blocking app startup

## Homepage (zekparser-homepage/)

Marketing/download site for `https://zekparser.com/`. Catppuccin Mocha dark theme. Google Tag Manager (`GTM-TJK722NR`) on all pages. Copyright: Joinkle (joinkle.com).

- **`index.html`** — Main landing page. Hero with version badge, screenshot grid (6 images in `screenshots/`), feature cards, how-it-works steps, download CTA. Nav: 3-column grid (logo left, nav buttons centered, Cash App/Venmo donate buttons right). Schema.org JSON-LD (SoftwareApplication, FAQPage, BreadcrumbList). Version displayed in hero-meta, CTA, and schema — **must be kept in sync** with `APP_VERSION` and `version_info.py` when bumping.
- **`chatparser.html`** — ChatParser download page. Schema.org JSON-LD with `softwareVersion`. Version in schema + download CTA button — **must be kept in sync** with `chatparser/bot.py` title and `chatparser/version_info.py`.
- **`saltyvision.html`** — "Coming Soon" page for SaltyVision, a crowdsourced item/XP/combat database. Explains the three planned databases (Items, Experience, Combat) and the API data pipeline from ZekParser sessions. Uses `body class="sv-page"` for page-specific CSS overrides. Same nav/donate layout as index.
- **`style.css`** — Shared styles for all pages. SaltyVision-specific styles prefixed with `.sv-` and scoped under `.sv-page`. Nav links styled as pill buttons with `.nav-active` purple fill for current page. `.btn-donate` orange (Catppuccin peach).
- **`screenshots/`** — 6 named PNGs: `overview-feed-expanded.png`, `encounters-multiple-kills.png`, `grand-overview-npc-stats.png`, `item-detail-drop-history.png`, `triggers-pattern-setup.png`, `encounters-active-dead.png`. Plus one placeholder for Experience Tracker.

## SaltyVision Database Backend (website/)

PHP/MySQL web application that receives data from ZekParser's API client. This is the server side of the `api_url` endpoint.

- **`api/submit.php`**: Receives batched combat events, loot events, items, NPCs from ZekParser sessions. Auth via HMAC-SHA256 (`api/auth.php`).
- **`sql/schema.sql`**: Tables: `players`, `npcs`, `items`, `combat_events`, `loot_events`.
- **Views**: `leaderboard.php`, `killfeed.php`, `npcs.php`, `npc_detail.php`, `items.php`, `item_detail.php`.

## Tools

- **`tools/parse_644b.py`**: Offline hex dump analyzer for 0x644B combat animation packets. Parses merged packets, standalone packets, and companion messages (UpdateHealth, ChatMessage, EndCasting) from log files.
- **`tools/Il2CppDumper-win-v6.7.46.zip`**: IL2CPP reverse engineering tool for finding memory offsets.

## Build Notes

Three PyInstaller `.spec` files exist:
- **`ZekParser.spec`**: ZekParser production build — includes `version='version_info.py'`, `upx=True`. Use this one for ZekParser.
- **`ChatParser.spec`**: ChatParser production build — includes `version='chatparser/version_info.py'`, `upx=True`. Use `pyinstaller --clean ChatParser.spec`.
- **`MNM Combat Parser.spec`**: Legacy — no version file, `upx=False`. Do not use for releases.

## Important Gotchas

- CRC32c is at the **back** of the packet, not front
- AES is CBC mode with per-packet IV (first 16 bytes), not ECB
- .NET Aes defaults to PKCS7 padding — must unpad after decrypt
- TypeInfo RVA `88407256` decimal = `0x544FCD8` hex (previous wrong conversion caused key read failures)
- Game binds UDP to 0.0.0.0 — connection matching must use port-only fallback
- Logger must have `logger.setLevel(DEBUG)` set on the logger itself; handler-level filtering alone is insufficient
- `read_string()` strips trailing null byte since LiteNetLib includes it in the length count. `_r_str` in parser.py strips all trailing control bytes `< 0x20` (EOT `0x04` appears in some LNL strings)
- Console output strips BEL characters (`\x07`) to prevent Windows terminal beeping on decoded packet data
- Spawn packet HP values from `_find_stats()` scan are frequently wrong (misaligned byte reads produce multiples of 256) — never trust them as damage baselines
- `parser/parser.py` is intentionally self-contained with duplicated logic from `core/` — do not add imports from `core/`
- `chatparser/bot.py` is intentionally self-contained — do not add imports from `core/` or `parser/`
- Melee auto-attack damage text ("You slash X for N damage") is in **ChatMessage (0x0040) channel 1**, NOT EndCasting (0x0056). Each melee hit sends 3 messages: `UpdateHealth` + `ChatMessage` + `0x644B` (animation). The 0x644B has both entity IDs and the verb but NOT the damage number — the damage value only exists in the ChatMessage English text
- ChatCombat messages have **no entity IDs** — target must be resolved by temporal correlation with the preceding `UpdateHealth`, not by name lookup (multiple NPCs share names)
- EndCasting text for non-combat actions ("Rainbow pulls you through a shimmering portal") will match broad verb patterns — use the `_MELEE_VERBS` whitelist, not `\w+`
- `config.json` `player_name` should be empty string `""` — the parser auto-detects it from outbound Autoattack/ChangeTarget packets and "Your..."/"You..." combat text patterns
- Never use `"_local"` string as a real entity ID — it's a sentinel placeholder for the local player before detection. Always resolve via `_local_player_eid` at consumption points and merge in `_mark_local_player`
- Wire format helpers in parser.py: `_r_u32`, `_r_i32`, `_r_u16`, `_r_u8`, `_r_bool`, `_r_float`, `_r_str` — all return `(value, new_offset)` or `(None, offset)` on bounds failure. `_r_str` strips all trailing control bytes `< 0x20` (not just `\x00` — LNL strings sometimes terminate with `0x04` EOT)
- ClientPartyUpdate (0x0380) class_hid field is NOT a LNL string — it's `[u8 0x00] [3 raw ASCII bytes] [u8 level]`. Standard `_r_str` reads the 0x00 + first class byte as a u16 length = huge number and fails. Parser reads the 3 bytes directly and validates as lowercase alpha
- `_r_str_nn` is a no-null string reader for ItemInformation (0x0080) and embedded ItemRecords: length field = strlen+1 (counts implicit null) but **null byte is NOT on wire** — reads `len-1` bytes. Do not confuse with `_r_str`
- ItemInformation (0x0080) has 7 resist fields (no holy resist), 11 boolean flags (not 3), and uses i32 for type/level fields (not u16). First 3 i32 after craft_class are `[damage][delay][AC]`
- AddItemToInventory (0x0063) embeds a full ItemRecord — the game does NOT send a separate 0x0080 for items looted via 0x0063. Looted items go to `_items` only (not `_inspected_items`)
- Auto-updater HTTP requests MUST set a custom `User-Agent` header — `zekparser.com` returns 403 for the default `Python-urllib/3.x` agent and for HEAD requests

