# ZekParser

A free, real-time DPS meter and combat log parser for **Monsters & Memories**. ZekParser captures network traffic directly from the game client, decrypts it on the fly, and displays live combat statistics — damage meters, per-encounter breakdowns, item drops, XP tracking, and configurable text triggers with audio alerts.

Single portable `.exe`. No install. No game file modification. Runs alongside the game and reads network data passively.

**Download**: [zekparser.com](https://zekparser.com/)

## Features

### Real-Time DPS Meter
Damage per second calculated live as combat happens. Every hit, spell, and ability is tracked the moment it lands. No log file parsing after the fact.

### Session Overview
Aggregated leaderboard across all encounters. Top players ranked by total damage with expandable per-ability breakdowns. Click any player to see exactly which abilities contributed what.

### Encounter Logging
Every fight tracked individually — mob name, total damage dealt, duration, DPS, and per-player contribution. Click into any encounter for the full damage breakdown with class tags and ability lists.

### Grand Overview
Combined statistics across your entire session. Per-player boxes with class/level, total damage, DPS, damage received, and full ability breakdowns. Per-NPC aggregation showing kill counts and average damage.

### Item Tracker
All loot drops logged with full item stats, effects, flags (MAGIC/NO DROP/UNIQUE), and which mob dropped them. Tracks drop frequency and timestamps. Never miss a drop.

### Experience Tracking
XP gains per kill with running totals, XP/hour calculation, and level-up detection. Automatically correlates XP events with the mob you just killed.

### Text Triggers
User-defined pattern matching against all combat text. Set up alerts for specific events — "tells you", "has been slain", "resisted" — with selectable Windows system sounds. Match counts tracked per pattern.

### Copy & Share
Select and copy data from any view. Formats a clean table you can paste directly into Discord or chat.

## Getting Started

### Download & Run (Recommended)

1. Download `ZekParser.exe` from [zekparser.com](https://zekparser.com/)
2. Add a Windows Defender exclusion for `ZekParser.exe` or its folder (unsigned exe triggers false positives)
3. Right-click → **Run as Administrator** (required for network capture)
4. Launch the game — ZekParser auto-detects the game process, finds the server connection, and starts parsing

### Run from Source

Requires Python 3.10+ on Windows.

```bash
pip install pycryptodome

# Run the GUI parser (requires Administrator terminal)
python parser/parser.py
```

## How It Works

ZekParser uses Windows raw sockets in promiscuous mode to capture all network traffic on the interface. It filters to packets matching the game's server connection, decrypts them using AES-256-CBC with keys extracted from the game process memory, then parses FishNet/LiteNetLib framing to extract game-level messages.

**The parser never modifies game files, injects code, or writes to game memory.** It is a passive network observer.

### Capture Pipeline

```
Game (mnm.exe) ──UDP/TCP──► Network
                               │
    Raw Socket (SIO_RCVALL) ───┘
              │
        IP/UDP header parse ──► filter by game connection (port matching)
              │
        AES-256-CBC decrypt (keys read from game memory via ReadProcessMemory)
              │
        LiteNetLib frame parse (Unreliable / Channeled / Merged sub-frames)
              │
        Game message extract (2-byte LE opcode + body)
              │
        Combat event parse ──► EntityTracker ──► GUI display
```

### Thread Architecture

| Thread | Role |
|---|---|
| **Main** | tkinter GUI event loop, `after()` polling for updates |
| **Capture** | Raw socket recv loop, pushes raw packets to queue |
| **Connection** | Polls Windows `iphlpapi` every 5s to track game TCP/UDP connections |
| **KeyWatcher** | Reads AES/HMAC/XOR keys from game memory every 5s |
| **Processor** | Decrypts packets, parses messages, feeds events to EntityTracker |

### Combat Data Sources

The game uses multiple message types to communicate combat information. No single message contains all the data needed to fully describe a combat event:

| Message | Contains | Missing |
|---|---|---|
| **UpdateHealth** (0x0022) | Target entity ID, new HP, max HP | Who caused the damage |
| **EndCasting** (0x0056) | Caster ID, target ID, English text with damage | Damage as a structured field (must regex parse) |
| **ChatMessage** (0x0040) | English text with melee damage | Any entity IDs at all |
| **Combat Animation** (0x644B) | Attacker ID, target ID, verb | Damage number |

Because no single packet contains (attacker, target, damage amount) together, the parser correlates across messages using temporal matching and entity ID tracking.

### Dual Damage Tracking

Every encounter tracks two independent damage values:

- **HP-delta damage** (`total_damage`): Computed from successive UpdateHealth messages. Captures ALL damage sources (spells, melee, DoTs, damage shields, reflected damage) but can be percentage-based for tough NPCs where the server reports HP as 0-100 instead of actual values.
- **Text-extracted damage** (`text_damage`): Parsed from combat text via regex. Always contains real damage numbers but may miss passive effects that don't generate text.

The UI displays `best_damage = max(text_damage, total_damage)`, handling both normal NPCs (where HP-delta is accurate) and percentage-HP bosses (where only text damage has real numbers).

### DPS Calculation

| Context | Formula | Description |
|---|---|---|
| **Encounter DPS** | `best_damage / (die_time - first_damage)` | Total encounter DPS across all players |
| **Player DPS (encounter)** | `player_best_dealt / encounter_duration` | Player's sustained contribution over the fight |
| **Player DPS (overview)** | `total_dealt / (last_hit - first_hit)` | Player's personal active DPS window |
| **Grand DPS** | `sum(all damage) / sum(all durations)` | Session-wide average DPS |

## GUI Layout

### Right Panel (always visible)

Dropdown switches between three views:

| View | Description |
|---|---|
| **Overview** | Session leaderboard — players ranked by total damage, click to expand ability breakdowns |
| **Encounters** | Live/dead NPC encounter list. Click for per-player detail with damage bars, class tags, abilities |
| **Grand Overview** | Aggregated stats — per-player boxes with full ability breakdowns + per-NPC kill aggregation |

### Left Panel (expandable)

Starts hidden. Click the expand arrow to show. Dropdown switches between:

| View | Description |
|---|---|
| **Feed** | Real-time scrolling combat log, color-coded by event type |
| **Items** | Clickable item drop list with stats preview. Click for full detail |
| **Triggers** | Pattern matching setup with audio alerts |
| **Experience** | XP gain tracking per kill with session summary and XP/hour |

Copy and Export buttons adapt to whichever view is active.

## Configuration

`config.json` at project root (created with defaults if missing):

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
}
```

| Field | Description |
|---|---|
| `player_name` | Leave empty `""` — auto-detected from combat text. Only set manually if auto-detect fails |
| `server_name` | Display label for the GUI title bar |
| `interface_ip` | `"auto"` to detect from game connections, or explicit IP like `"10.0.0.5"` |

## Requirements

- **Windows 10 or 11**
- **Run as Administrator** (required for raw socket capture)
- **Game running on the same machine**
- No dependencies to install (standalone exe)

For running from source: Python 3.10+, `pycryptodome`

## Project Structure

```
parser/parser.py        # GUI entry point — fully self-contained, zero imports from core/
parser/api_client.py    # Optional remote API submission (HMAC-signed batched uploads)
parser/triggers.json    # Persisted trigger patterns
mnm.py                  # Headless CLI entry point (console logging + NPC database)
core/capture.py         # Raw socket capture engine
core/connections.py     # Game connection monitoring (Windows iphlpapi)
core/memory.py          # IL2CPP memory reading (ReadProcessMemory)
core/decrypt.py         # AES-256-CBC + CRC32c + HMAC decrypt pipeline
core/parser.py          # IP/UDP/TCP + LiteNetLib frame parsing
core/combat.py          # Game message parsing (SpawnEntity, combat events, party data)
core/opcodes.py         # 355 known game message IDs
core/npc_database.py    # NPC spawn data CSV recorder
config.json             # Runtime configuration
version_info.py         # Windows exe metadata (PyInstaller --version-file)
zekparser-homepage/     # Marketing landing page for zekparser.com
```

### Building the Exe

```bash
pip install pyinstaller pycryptodome

pyinstaller --onefile --noconsole --name ZekParser \
    --uac-admin --version-file version_info.py \
    --collect-all pycryptodome "parser/parser.py"

# Output: dist/ZekParser.exe
```

The exe is unsigned — users should add a Windows Defender exclusion to prevent false positive quarantine.

### CLI Tool

`mnm.py` is a headless CLI alternative for background logging, data collection, and protocol analysis:

```bash
python mnm.py                          # Normal operation
python mnm.py --dump-keys              # Read encryption keys and exit
python mnm.py --log-level DEBUG        # Verbose output
python mnm.py --no-wait                # Fail immediately if game isn't running
python mnm.py -p other.exe -i 10.0.0.5  # Custom process name and interface IP
```

## Known Limitations

- **Player class/level**: Only available from SpawnEntity (at spawn) and ClientPartyUpdate (on `/reload` or party changes). Other players' class/level depends on these packets arriving while the parser is running.
- **Encryption key timing**: Keys are read from game memory after login. Packets sent before key acquisition (including initial player state) are lost.
- **Entity ID reuse**: The game reuses entity IDs for newly spawned NPCs. The parser detects name changes on SpawnEntity to retire old encounters, but edge cases exist.
- **Melee damage attribution**: Melee auto-attacks arrive as ChatMessage text with no entity IDs. The parser uses temporal correlation with UpdateHealth, which can fail when multiple NPCs take damage simultaneously.
- **Percentage-HP distortion**: Tough NPCs report percentage-based HP (max_hp=100). The dual-tracking system mitigates this but isn't perfect under packet loss.
- **Experience tracking**: Requires two kills to start — the first kill sets the XP baseline. XP is per-level progress and resets on level-up.

## DPS Methodology Deep Dive

For those interested in the details of how DPS is calculated and how it compares to other MMO parsers.

### The Attribution Problem

Because no single packet contains (attacker, target, damage amount) together:

1. **BeginCasting** arrives → records `last_attacker[target_eid] = caster_eid`
2. **UpdateHealth** arrives → computes HP delta, credits to `last_attacker[target_eid]`
3. **EndCasting/ChatMessage** text → regex extracts real damage number as `text_damage`

This temporal correlation is inherently imperfect. Simultaneous attackers, DoTs, and damage shields can be misattributed.

### What This Captures

- **All damage sources**: HP-delta tracking captures spells, melee, DoTs, damage shields, reflected damage, procs — anything that reduces the target's HP
- **Real damage numbers**: Text-extracted damage bypasses the percentage-HP problem on tough NPCs
- **Per-encounter isolation**: Each NPC is tracked separately. Downtime between pulls does not inflate duration
- **Dual-tracking fallback**: When HP-delta is percentage-based, text damage provides real numbers. When text damage misses passive sources, HP-delta fills the gap

### Limitations

1. **Wall-clock duration**: Duration runs from first damage to death. Idle time within an encounter (kiting, running back) inflates the denominator
2. **No active-time filtering**: All time between first and last hit counts, even if the player stopped attacking
3. **Attribution errors**: Since UpdateHealth has no attacker field, damage is credited to whoever most recently cast at the target. Simultaneous attackers can get credit swapped
4. **Missed damage**: If no BeginCasting/EndCasting was seen for a target before its UpdateHealth arrives, the damage is recorded for the encounter total but not credited to any specific player

### Alternative DPS Methods (Not Yet Implemented)

| Method | What It Measures | Used By |
|---|---|---|
| **Active-Time DPS** | Damage / time spent attacking (gaps excluded) | GW2 ArcDPS, FFXIV ACT, WoW Details! |
| **Rolling Window DPS** | Damage in last N seconds | WoW Details!, EQ2 ACT |
| **Effective DPS** | Target max HP / kill time | EQ GamParse |
| **Peak DPS** | Best N-second burst window | WoW Warcraft Logs, FFXIV FFLogs |
| **rDPS** | Buff-adjusted contribution | GW2 ArcDPS, FFXIV FFLogs |

The most impactful future improvement would be **active-time DPS** (the standard metric in modern MMO parsers) and **rolling window DPS** for real-time monitoring during fights.

## License

Copyright 2026 Joinkle
