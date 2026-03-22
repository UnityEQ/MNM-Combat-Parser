# ZekParser & DadQuest

Free, real-time tools for **Mammary Monsters**. No install. No game file modification. Runs alongside the game and reads network data passively.

**Download**: [zekparser.com](https://zekparser.com/)

---

## ZekParser

A live DPS meter and combat log parser. Captures network traffic directly from the game client, decrypts it on the fly, and displays live combat statistics — damage meters, per-encounter breakdowns, item drops, XP tracking, and configurable text triggers with audio alerts.

Single portable `.exe`. Right-click → Run as Administrator.

### Features

- **Real-Time DPS Meter** — Every hit, spell, and ability tracked the moment it lands
- **Session Overview** — Aggregated leaderboard with expandable per-ability breakdowns
- **Encounter Logging** — Every fight tracked individually with per-player contribution, class tags, and ability lists
- **Grand Overview** — Combined session statistics with per-player and per-NPC aggregation
- **Item Tracker** — All loot drops with full stats, effects, flags, drop frequency, and source mob
- **Experience Tracking** — XP gains per kill with XP/hour and level-up detection
- **Text Triggers** — Pattern matching against combat text with audio alerts
- **Copy & Share** — Clean formatted tables for pasting into Discord
- **Auto-Update** — Checks for new versions on startup and updates automatically

### Getting Started

1. Download `ZekParser.exe` from [zekparser.com](https://zekparser.com/)
2. Add a Windows Defender exclusion for `ZekParser.exe` or its folder (unsigned exe triggers false positives)
3. Right-click → **Run as Administrator** (required for network capture)
4. Launch the game — ZekParser auto-detects the game process and server connection
5. Type `/reload` in-game — this identifies your character. Solo players are detected automatically; in a group, click your name from the list

### GUI Layout

**Right Panel** (always visible) — dropdown switches between:

| View | Description |
|---|---|
| **Overview** | Session leaderboard — players ranked by total damage, click to expand ability breakdowns |
| **Encounters** | Live/dead NPC encounter list. Click for per-player detail with damage bars |
| **Grand Overview** | Aggregated stats — per-player boxes + per-NPC kill aggregation |

**Left Panel** (expandable) — starts hidden, click the expand arrow:

| View | Description |
|---|---|
| **Feed** | Real-time scrolling combat log, color-coded by event type |
| **Items** | Clickable item drop list with stats preview. Click for full detail |
| **Triggers** | Pattern matching setup with audio alerts |
| **Experience** | XP gain tracking per kill with session summary and XP/hour |

---

## DadQuest

A semi-transparent overlay for chat trigger matching, keyboard automation, opcode inspection, and entity discovery. Always-on-top at 75% opacity — sits over the game without blocking it.

Single portable `.exe`. Right-click → Run as Administrator.

**Download**: [zekparser.com/dadquest](https://zekparser.com/dadquest.html)

### Features

- **Text Triggers** — Case-insensitive pattern matching against combat/chat text with configurable key press sequences (loop, once, or sound-only modes)
- **Keyboard Automation** — When a trigger fires, sends key presses to the game window via `SendInput` with configurable delays and loop counts
- **Opcode Browser** — Live message inspector with filter categories (Chat, Combat, All), search, per-message detail view with parsed fields + raw hex dump
- **Discovery Tab** — Tracks unique NPC and PC names from entity spawns. Two-column display with copy/reset
- **Discovery Alerts** — Set patterns that trigger a chime sound + yellow highlight when matching entities spawn. Collapsible panel with NPC/PC toggle per alert
- **Chime Sound Library** — 28 sounds across 7 themes (big-sur, chime, mario, material, pokemon, sonic, zelda) × 4 types (success, warning, error, info)
- **Opcode Triggers** — Match specific field values in specific opcodes (e.g. `0x0020.name = "Poacher"`)
- **Auto-Target** — Extract speaker name from matched text for `/target` automation
- **Fizzle Detection** — Detects spell fizzles and auto-retries key presses
- **Auto-Update** — Checks for new versions on startup and updates automatically

### Getting Started

1. Download `DadQuest.exe` from [zekparser.com/dadquest](https://zekparser.com/dadquest.html)
2. Add a Windows Defender exclusion
3. Right-click → **Run as Administrator**
4. Launch the game — DadQuest auto-connects

### GUI Layout

- **Connection Status** — Shows capture state, game connection, key status
- **Main Tab** — Text trigger list with pattern entry, mode cycling (Loop/Once/Sound), sound dropdown, expandable key pair configuration
- **Opcode Tab** — Live message browser with category filters, search, and detail view. Create opcode triggers directly from message details
- **Discovery Tab** — Alert bar at top (collapsible, scrollable), NPC/PC name columns below. Matching names highlighted in yellow

---

## How It Works

Both tools use Windows raw sockets in promiscuous mode to capture network traffic. They filter packets matching the game's server connection, decrypt using AES-256-CBC with keys extracted from game process memory, then parse FishNet/LiteNetLib framing to extract game messages.

**Neither tool modifies game files, injects code, or writes to game memory.** They are passive network observers.

```
Game (mnm.exe) ──UDP/TCP──► Network
                               │
    Raw Socket (SIO_RCVALL) ───┘
              │
        IP/UDP header parse ──► filter by game connection
              │
        AES-256-CBC decrypt (keys read from game memory)
              │
        LiteNetLib frame parse
              │
        Game message extract ──► Parser/Tracker ──► GUI
```

## Requirements

- **Windows 10 or 11**
- **Run as Administrator** (required for raw socket capture)
- **Game running on the same machine**
- No dependencies to install (standalone exe)

### Run from Source

Requires Python 3.10+ on Windows.

```bash
pip install pycryptodome chime

# ZekParser GUI
python parser/parser.py

# DadQuest GUI
python dadquest/bot.py

# Headless CLI (console logging + NPC database)
python mnm.py
```

## Building

```bash
pip install pyinstaller pycryptodome chime

# ZekParser (output: dist/ZekParser.exe)
pyinstaller --onefile --noconsole --name ZekParser \
    --uac-admin --version-file version_info.py \
    --collect-all pycryptodome "parser/parser.py"

# DadQuest (output: dist/DadQuest.exe)
pyinstaller --clean DadQuest.spec
```

Both exes are unsigned — users should add a Windows Defender exclusion to prevent false positive quarantine.

## Configuration

`config.json` at project root (created with defaults if missing):

| Field | Description |
|---|---|
| `player_name` | Leave empty `""` — auto-detected from `/reload` party data |
| `server_name` | Display label for the GUI title bar |
| `interface_ip` | `"auto"` to detect from game connections, or explicit IP |

## Known Limitations

- **Player class/level**: Sourced from ClientPartyUpdate (on `/reload`). Other players' class/level depends on SpawnEntity or party data arriving while the parser is running
- **Encryption key timing**: Keys are read from game memory after login. Packets sent before key acquisition are lost
- **Entity ID reuse**: The game reuses entity IDs for newly spawned NPCs. The parser detects name changes to retire old encounters, but edge cases exist
- **Melee damage attribution**: Melee auto-attacks arrive as text with no entity IDs. Temporal correlation with HP updates can fail when multiple NPCs take damage simultaneously
- **Experience tracking**: Requires two kills to start — the first kill sets the XP baseline

## License

Copyright 2026 Joinkle
