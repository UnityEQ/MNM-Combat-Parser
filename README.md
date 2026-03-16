# MNM Combat Parser

A real-time combat log parser for Monsters & Memories (MNM). Captures network traffic directly from the game client, decrypts it, and displays live combat statistics including damage meters, DPS tracking, per-encounter breakdowns, item drops, and configurable text triggers with audio alerts.

Runs as a standalone Windows GUI application. Requires Administrator privileges for raw socket packet capture.

## Requirements

- **Windows 10/11** (raw sockets require Windows APIs)
- **Administrator privileges** (required for promiscuous-mode socket capture)
- **Python 3.10+**
- **pycryptodome** (auto-installed on first run if missing)

```
pip install pycryptodome
```

## Two Entry Points

### `parser/parser.py` -- GUI Combat Parser

A standalone tkinter GUI. Fully self-contained -- duplicates the entire capture/decrypt/parse pipeline internally and has zero imports from `core/`. Debug logs go to `parser/logs/`.

```
python parser/parser.py
```

### `mnm.py` -- Headless CLI Tool

Captures packets, decrypts, and logs combat events to console and rotating log files. Good for background logging, data collection, and protocol analysis.

```
python mnm.py
python mnm.py --dump-keys           # Read encryption keys from memory and exit
python mnm.py --log-level DEBUG     # Verbose output
python mnm.py --no-wait             # Fail immediately if game isn't running
python mnm.py -p other.exe -i 10.0.0.5  # Custom process/interface
```

## Capture Pipeline

```
mnm.exe (game) ──UDP──> Network
                          │
Raw Socket (SIO_RCVALL) ──┘
          │
    IP/UDP header parse ──> filter by game connection (port matching)
          │
    AES-256-CBC decrypt (keys read from game memory via ReadProcessMemory)
          │
    LiteNetLib frame parse (Unreliable / Channeled / Merged sub-frames)
          │
    Game message extract (2-byte LE opcode + body)
          │
    Combat event parse ──> EntityTracker ──> GUI display
```

The parser uses Windows raw sockets in promiscuous mode (`SIO_RCVALL`) to capture all network traffic on the interface, filters it to packets matching the game's server connection, decrypts using AES-256-CBC with keys extracted from the game process memory (`GameAssembly.dll` static fields via `ReadProcessMemory`), then parses the FishNet/LiteNetLib framing to extract game-level messages.

### Thread Architecture

| Thread | Role |
|---|---|
| **Main** | tkinter GUI event loop, `after()` polling for updates |
| **Capture** | Raw socket recv loop, pushes raw packets to queue (max 10k) |
| **Connection** | Polls Windows `iphlpapi` every 5s to track game TCP/UDP connections |
| **KeyWatcher** | Reads AES/HMAC/XOR keys from game memory every 5s |
| **Processor** | Decrypts packets, parses messages, feeds events to EntityTracker |

All threads communicate via `queue.Queue` and `threading.Lock`. The GUI polls event queues using `tkinter.after()` at 200ms intervals.

## Combat Data Sources

The game uses multiple message types to communicate combat information. No single message contains all the data needed to fully describe a combat event:

### UpdateHealth (0x0022)

```
[entity_id: u32] [new_hp: i32] [max_hp: i32]
```

Tells you WHO lost health and by HOW MUCH (delta from previous HP value). Does **not** include who caused the damage. The parser must correlate damage attribution from BeginCasting/EndCasting events that arrive nearby in time via `last_attacker[target_eid]`.

For tough/boss NPCs, the server sometimes sends **percentage-based HP** (max_hp=100 instead of actual HP), making delta values useless for real damage numbers.

### EndCasting (0x0056)

```
[caster_id: u32] [target_id: u32] [text: string]
```

Spell/ability result text as English strings: `"Your Fireball hits a goblin for 200 points of Fire Damage."` Has both entity IDs but the damage number is embedded in natural language text requiring regex extraction. Also carries non-combat text (flavor text, crafting, buff notifications) with no type flag to distinguish them.

Six regex patterns parse the text in priority order:

1. Third-person spell: `"X's Ability hits Y for N points of Type Damage."`
2. Local player spell: `"Your Ability hits Y for N points of damage."`
3. Local melee + damage: `"You slash Y for N points of damage."`
4. Third-person melee + damage: `"Bannin slashes Y for N points of damage."`
5. Local melee, no damage: `"You kick Y."`
6. Third-person melee, no damage: `"Lilyth kicks Y."`

Patterns 3-6 use a `_MELEE_VERBS` whitelist (~40 verbs) to prevent non-combat verbs from creating false matches.

### ChatMessage (0x0040, channel 1)

```
[channel: u32] [text: string] [6 trailing bytes]
```

Melee auto-attack damage as English text: `"You slash a goblin for 52 points of damage."` Has **no entity IDs** -- attacker and target must be inferred from text content and correlated with the most recent UpdateHealth via temporal matching (the target's UpdateHealth always arrives immediately before its ChatMessage).

### Combat Animation (0x644B)

```
[attacker_eid: u32] [anim_type: u8] [verb: string]
[defender_eid: u32] [anim_type: u8] [verb: string]
```

Accompanies every melee hit. Has both entity IDs and the attack verb ("slash", "punch", "stab", "miss") but **no damage number**. Used for attacker attribution when pairing with UpdateHealth.

### The Attribution Problem

Because no single packet contains (attacker, target, damage amount) together:

1. **BeginCasting** arrives -> records `last_attacker[target_eid] = caster_eid`
2. **UpdateHealth** arrives -> computes HP delta, credits to `last_attacker[target_eid]`
3. **EndCasting/ChatMessage** text -> regex extracts real damage number as `text_damage`

This temporal correlation is inherently imperfect. Simultaneous attackers, DoTs, and damage shields can be misattributed.

## Encounter System

The `EntityTracker` maintains per-NPC encounter records keyed by entity ID. An `Encounter` is created when the first damage event targets a known NPC (entity_type != 0).

### Per-Encounter Data

| Field | Source | Description |
|---|---|---|
| `total_damage` | UpdateHealth deltas | Sum of HP reductions (may be percentage-based for tough NPCs) |
| `text_damage` | EndCasting/ChatMessage regex | Sum of damage numbers extracted from combat text (always real values) |
| `best_damage` | `max(text_damage, total_damage)` | Whichever is higher, used for display |
| `start_time` | First UpdateHealth showing damage | Encounter start timestamp |
| `end_time` | Die (0x0013) message | Encounter end timestamp (or `now()` if alive) |
| `players` | Per-attacker dict | Each player's dealt damage, received damage, abilities, timestamps |

### Per-Player Per-Encounter Data

| Field | Description |
|---|---|
| `dealt` | HP-delta damage credited to this player (from UpdateHealth attribution) |
| `text_dealt` | Text-extracted damage credited to this player (from combat text regex) |
| `received` | Damage this player received from the NPC |
| `abilities` | Dict of ability_name -> total damage dealt by that ability |
| `first` / `last` | Timestamps of first and last damage by this player |

### PvP Encounters

Created when both attacker and target are entity_type == 0 (both players). PvP encounters are gated: a confirmed player-on-player UpdateHealth damage event must establish the encounter before text damage gets attributed. This prevents ambient player HP updates from creating ghost encounters.

## DPS Calculation

### Current Implementation

The parser tracks two parallel damage values per encounter and uses whichever is higher.

#### HP-Delta Damage (`total_damage`)

Computed from successive UpdateHealth messages:

```
damage = previous_hp - new_hp    (negative delta = damage taken)
```

Accumulated for every UpdateHealth showing reduced HP on the encounter target. Captures ALL damage sources (spells, melee, DoTs, damage shields, reflected damage) but can be **percentage-based** for tough NPCs where the server reports HP as 0-100 instead of actual values.

#### Text-Extracted Damage (`text_damage`)

Parsed from EndCasting and ChatMessage combat text via regex:

```python
match = re.search(r'for (\d+)', text)    # "... for 252 points of Fire Damage."
```

Always contains the **real damage number** (never percentage-based) but only captures damage that produces a combat text message. Some passive effects (DoTs ticking between combat text windows, damage shields) may not generate text consistently.

#### Best Damage

```python
best_damage = max(text_damage, total_damage)
```

Handles both cases:
- **Normal NPCs**: `total_damage` is accurate, `text_damage` may miss some passive sources
- **Percentage-HP NPCs**: `text_damage` has real numbers, `total_damage` is meaningless (1-11 per hit)

#### Encounter DPS

```python
duration = end_time - start_time          # Die timestamp minus first damage
encounter_dps = best_damage / duration    # Total encounter DPS (all players)
```

- `start_time`: timestamp of the first UpdateHealth showing damage to this NPC
- `end_time`: timestamp of the Die message, or `time.time()` if still alive
- Minimum duration clamped to 0.1s to prevent division by zero

#### Per-Player DPS (Encounter Detail View)

Each player's best dealt damage within an encounter divided by the encounter's total duration:

```python
player_dealt = max(player.text_dealt, player.dealt)
player_dps = player_dealt / encounter.duration
```

All players share the same denominator (encounter duration). This answers: "What was this player's sustained contribution over the fight?"

#### Per-Player DPS (Damage Board -- Right Panel)

The right-panel top-20 leaderboard uses per-player first/last damage timestamps:

```python
elapsed = max(last_dealt_time - first_dealt_time, 1.0)    # min 1 second
player_dps = total_dealt / elapsed
```

This measures each player's personal DPS window (first hit to last hit) rather than the encounter duration. It answers: "How fast was this player dealing damage while they were active?"

#### Grand Total DPS (Totals View)

Sums all encounter damage and duration across every encounter:

```python
grand_dps = sum(enc.best_damage) / sum(enc.duration)
```

Per-player grand DPS uses accumulated encounter durations as the divisor:

```python
player_active_duration = sum(duration of encounters this player participated in)
player_grand_dps = player_total_dealt / player_active_duration
```

### What This DPS Calculation Captures

- **All damage sources**: HP-delta tracking captures spells, melee, DoTs, damage shields, reflected damage, procs -- anything that reduces the target's HP.
- **Real damage numbers**: Text-extracted damage bypasses the percentage-HP problem on tough NPCs.
- **Per-encounter isolation**: Each NPC is tracked separately. Downtime between pulls does not inflate duration.
- **Dual-tracking fallback**: When HP-delta is percentage-based, text damage provides real numbers. When text damage misses passive sources, HP-delta fills the gap.

### Limitations

1. **Wall-clock duration**: Duration runs from first damage to death. Idle time within an encounter (kiting, running back, waiting for a pull) inflates the denominator and lowers DPS.

2. **No active-time filtering**: All time between first and last hit counts, even if the player stopped attacking for extended periods mid-fight.

3. **Attribution errors**: Since UpdateHealth has no attacker field, damage is credited to whoever most recently cast at the target. Simultaneous attackers can get credit swapped. Damage-over-time effects are typically credited to the last attacker, not the DoT caster.

4. **Percentage-HP edge cases**: `best_damage = max(text, hp)` assumes one or the other is reliable. If both are partially incomplete (missed text + percentage HP), neither value is accurate.

5. **Missed damage**: If no BeginCasting/EndCasting was seen for a target before its UpdateHealth arrives, the HP-delta damage is recorded for the encounter total but not credited to any specific player.

6. **Unresolved entities**: Players whose SpawnEntity or UpdateState was never received show as "Entity#NNNN" until combat text reveals their name.

## Alternative DPS Calculation Methods

For reference, here is how other MMO combat parsers calculate DPS and how this parser could be adapted to match.

### 1. Active-Time DPS

**Used by**: GW2 ArcDPS, FFXIV ACT, WoW Details!

Instead of wall-clock encounter duration, only count time when the player is actively dealing damage. Gaps between actions exceeding a threshold (typically 3-5 seconds) are excluded:

```
active_time = sum of intervals between consecutive hits where gap < threshold
active_dps = total_damage / active_time
```

This is the most common DPS metric in modern MMO parsers because it rewards sustained activity and doesn't penalize players for mechanics that force them to stop attacking (dodging, running, stunned).

**How to implement here**: Currently, each player's encounter entry tracks `first` and `last` timestamps. To support active-time DPS, store a list of all hit timestamps per player per encounter. On render, iterate the list and sum only intervals where `timestamps[i+1] - timestamps[i] < threshold`. The threshold could be configurable (default 5s). Memory cost is one float per hit per player per encounter.

### 2. Rolling Window DPS (Real-Time)

**Used by**: WoW Details! (current fight DPS), EQ2 ACT

Show DPS over a sliding time window (e.g., last 10 or 30 seconds) rather than cumulative:

```
window_dps = damage_dealt_in_last_N_seconds / N
```

Answers: "How fast am I dealing damage right now?" Useful for monitoring burst phases, adjusting rotation, or detecting when DPS drops.

**How to implement here**: Maintain a `deque` of `(timestamp, damage)` tuples per entity. On each refresh (every 1 second), discard entries older than the window, sum the remaining damage, divide by window size. Display as a separate column alongside cumulative DPS. Window size could be configurable (10s, 30s, 60s).

### 3. Effective DPS

**Used by**: EverQuest GamParse, EQ GINA

Uses the target's actual HP pool as the damage baseline instead of summing deltas:

```
effective_dps = target_max_hp / kill_duration
group_effective_dps = target_max_hp / (die_time - first_damage_time)
```

Individual player contribution: `(player_dealt / total_dealt) * effective_dps`

This eliminates overkill damage and percentage-HP distortion because you're dividing the known HP pool by the time it took to deplete it.

**How to implement here**: The parser receives `max_hp` from UpdateHealth. For NPCs with real (non-percentage) HP values, `effective_dps = max_hp / duration` is trivial. The challenge is distinguishing percentage-HP mobs (max_hp=100) from NPCs that genuinely have 100 HP. A heuristic: if `max_hp <= 100` and `text_damage` significantly exceeds `total_damage`, it's likely percentage-based.

### 4. Peak / Burst DPS

**Used by**: WoW Warcraft Logs, FFXIV FFLogs

Track the highest DPS achieved over any N-second window during the fight:

```
peak_dps = max(damage_in_any_N_second_window) / N
```

Identifies the player's maximum burst potential. Useful for evaluating cooldown usage and opener effectiveness.

**How to implement here**: Same sliding window data structure as rolling DPS, but instead of showing the current window, track and display the maximum value seen. Report both "current DPS" and "peak DPS" columns.

### 5. rDPS / aDPS (Raid Contribution DPS)

**Used by**: GW2 ArcDPS, FFXIV FFLogs

- **rDPS** (raid DPS): Credits damage increases from buffs/debuffs to the player who applied them, not the player who dealt the buffed damage. If a Bard's song increases a Warrior's damage by 10%, that 10% is attributed to the Bard.
- **aDPS** (actual DPS): Raw damage dealt, including all external buff contributions.

**Not currently feasible**: Would require parsing buff applications (AddBuffIcon 0x0053), knowing each buff's damage modifier, and modeling the counterfactual "what would this hit have been without the buff." The game doesn't expose buff modifier values in packets.

### 6. Damage Taken Per Second (DTPS)

**Used by**: WoW Details!, FFXIV ACT

Same as DPS but for damage received:

```
dtps = total_damage_received / encounter_duration
```

**Partially implemented**: The parser tracks `player.received` per encounter (damage received by each player). Dividing by encounter duration gives DTPS. Currently displayed as a raw number in the Tanking section of Totals view.

### 7. Healing Per Second (HPS)

**Used by**: Most MMO parsers

```
hps = total_healing_done / encounter_duration
```

**Partially available**: The parser detects heal events from EndCasting text (`"heals X for N Health"`) and tracks healing amounts. Adding an HPS display would follow the same pattern as DPS calculation.

### Summary: Comparison Table

| Method | What It Measures | Denominator | Handles Idle Time | Implemented |
|---|---|---|---|---|
| **Encounter DPS** | Total damage / fight length | First hit to death | No | Yes |
| **Personal Window DPS** | Damage / player's active window | First hit to last hit | Partially | Yes (damage board) |
| **Active-Time DPS** | Damage / time spent attacking | Sum of active intervals | Yes | No |
| **Rolling Window DPS** | Damage in last N seconds | Fixed window (e.g. 10s) | Yes | No |
| **Effective DPS** | Max HP / kill time | Kill duration | No | No |
| **Peak DPS** | Best N-second burst | Fixed window (e.g. 10s) | N/A | No |
| **rDPS** | Buff-adjusted contribution | Encounter duration | No | Not feasible |

The most impactful improvement would be **active-time DPS**, as it's the standard metric used by ArcDPS, ACT, and Details! and directly addresses the wall-clock duration limitation. **Rolling window DPS** would add the most user-facing value for real-time monitoring during fights.

## GUI Layout

### Left Panel (tabbed: Feed / Items / Triggers)

- **Feed**: Real-time scrolling combat log. Color-coded by event type (damage, heals, deaths, buffs, combat text). Supports pause, CSV export, and chat log viewer.
- **Items**: Clickable item drop tracker. Shows item name, drop count, compact stats preview (DMG/AC/primary stats). Click for full detail: HID, type/slot/level, flags, all stats, effects, drop history with NPC sources and timestamps.
- **Triggers**: User-defined text pattern matching with audio alerts. Substring match against all chat, combat text, and death messages. Select from Windows system sounds. Patterns persist to `triggers.json`.

### Right Panel

- **Encounter List** (default): Live and dead NPC encounters sorted by recency. Shows NPC name, class, total damage, duration. Click for detail. Right-click to hide.
- **Encounter Detail**: Per-player damage breakdown for a single encounter. Dealt damage, DPS, damage received, ability breakdown by damage.
- **Totals View**: Aggregated stats across all encounters. Grand total damage/DPS/duration, per-player boxes with class/level/dealt/received/DPS and top abilities, per-NPC tanking section.
- **Damage Board**: Real-time top-20 damage dealt leaderboard with personal DPS.

### Header

Left panel toggle (collapse/expand with window resize), active tab buttons, pause, chat log, CSV export (context-dependent).

## Configuration

`config.json` (optional, created with defaults if missing):

```json
{
    "player_name": "",
    "server_name": "Beta PvP",
    "process_name": "mnm.exe",
    "interface_ip": "auto",
    "log_level": "INFO",
    "capture_filter": {
        "protocols": ["UDP", "TCP"],
        "exclude_ports": [80, 443, 53]
    },
    "api_enabled": false
}
```

- `player_name`: Leave empty for auto-detection from combat text ("Your X hits Y" patterns)
- `interface_ip`: `"auto"` to detect from game connections, or explicit IP like `"10.0.0.5"`

## Project Structure

```
parser/parser.py        # GUI entry point (self-contained, no core/ imports)
parser/api_client.py    # Optional remote API submission (HMAC-signed)
parser/triggers.json    # Persisted trigger patterns (auto-created)
mnm.py                  # CLI entry point
core/capture.py         # Raw socket capture engine
core/connections.py     # Game connection monitoring (iphlpapi)
core/memory.py          # IL2CPP memory reading (ReadProcessMemory)
core/decrypt.py         # AES-CBC + CRC32c + HMAC decrypt pipeline
core/parser.py          # IP/UDP/TCP + LiteNetLib frame parsing
core/combat.py          # Game message parsing (SpawnEntity, combat events)
core/opcodes.py         # 355 known game message IDs
core/npc_database.py    # NPC spawn data CSV recorder
config.json             # Runtime configuration
data/npc_database.csv   # Recorded NPC spawn data
```

## Known Limitations

- **Player class/level**: The game only sends player class and level via UpdateState (at login/zone-in, before parser has keys) and ClientPartyUpdate (on party membership changes). Other players' class/level display depends on these packets arriving while the parser is running.
- **Encryption key timing**: Keys are read from game memory after login. Packets sent before key acquisition (including initial player state) are lost.
- **Entity ID reuse**: The game reuses entity IDs for newly spawned NPCs. The parser detects name changes on SpawnEntity to retire old encounters, but edge cases exist.
- **Melee damage attribution**: Melee auto-attacks arrive as ChatMessage text with no entity IDs. The parser uses temporal correlation with UpdateHealth (target's HP update always immediately precedes its ChatMessage), which can fail when multiple NPCs share the same name.
- **Spawn HP unreliable**: SpawnEntity HP values are frequently misaligned byte reads producing garbage. The parser ignores spawn HP and uses the first UpdateHealth as the real baseline.
- **Percentage-HP distortion**: Tough NPCs report max_hp=100 (percentage). The dual-tracking system (HP-delta + text-extracted) mitigates this but isn't perfect under packet loss.
