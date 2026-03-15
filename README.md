# MNM Network Capture Tool

A Windows network capture and analysis tool for the MNM Unity MMO. Intercepts game traffic in real-time, decrypts it using keys read from game memory, and parses the FishNet/LiteNetLib protocol into human-readable combat events, damage meters, and item tracking.

Built with Python stdlib + ctypes + pycryptodome. No packet injection or modification -- read-only passive capture.

## Requirements

- **Windows 10/11** (raw sockets require Windows APIs)
- **Administrator privileges** (required for promiscuous-mode socket capture)
- **Python 3.10+**
- **pycryptodome** (only external dependency)

```
pip install pycryptodome
```

## Two Entry Points

### `mnm.py` -- Headless CLI Tool

Captures packets, decrypts, and logs combat events to console and rotating log files. Good for background logging and data collection.

```
# Basic usage (requires admin terminal)
python mnm.py

# Read encryption keys from game memory and exit
python mnm.py --dump-keys

# Verbose output
python mnm.py --log-level DEBUG

# Fail immediately if game isn't running (don't wait)
python mnm.py --no-wait

# Custom process name and network interface
python mnm.py -p other.exe -i 10.0.0.5
```

**What it does:**
- Waits for `mnm.exe` to launch (or attach immediately with `--no-wait`)
- Monitors the game's network connections via Windows iphlpapi
- Reads AES-256 encryption keys from the game's IL2CPP memory (GameAssembly.dll)
- Captures all UDP/TCP traffic on the game's ports using raw sockets
- Decrypts packets (CRC32c + AES-256-CBC + PKCS7)
- Parses LiteNetLib frames and extracts game messages (355 known opcodes)
- Logs combat events to console and rotating log files in `logs/`
- Records NPC spawn data to `data/npc_database.csv`
- Prints stats every 10 seconds (packets matched, bytes in/out, active connections, key status)

### `parser/parser.py` -- GUI Combat Parser

A standalone tkinter GUI that does everything `mnm.py` does plus provides a real-time combat feed, damage meter with per-encounter breakdowns, and an item drop tracker.

```
# Launch GUI (requires admin terminal)
python parser/parser.py
```

**Features:**
- **Combat Feed** (left panel): Real-time scrolling feed of combat events -- damage dealt/received, heals, deaths, spell casts. Color-coded by event type. Pauseable and exportable to CSV.
- **Damage Meter** (right panel): Per-encounter damage tracking with DPS calculations. Click an encounter to see per-player breakdown. Encounters split into Active and Dead sections. Totals view aggregates across all encounters of the same NPC type.
- **Item Tracker**: Toggle the left panel to see looted items with counts. Click an item for full stats (damage, AC, stats, resists, effects, description, drop history).
- **PvP Tracking**: Detects player-vs-player combat and tracks it as encounters alongside NPC fights.
- **Auto-detection**: Player name auto-detected from combat text. Encryption keys read from game memory automatically.

**GUI is fully self-contained** -- it duplicates the entire capture/decrypt/parse pipeline internally and has zero imports from `core/`. Debug logs go to `parser/logs/`.

## Configuration

Edit `config.json` in the project root:

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
  }
}
```

- `player_name`: Leave empty -- auto-detected from combat text
- `interface_ip`: `"auto"` to detect from game connections, or explicit IP like `"10.0.0.5"`
- `exclude_ports`: Skip common non-game traffic (HTTP, HTTPS, DNS)

## How It Works

```
Raw Socket (SIO_RCVALL)
    -> IP header parse
    -> UDP/TCP header parse
    -> Filter by game process connections
    -> Strip CRC32c (last 4 bytes)
    -> AES-256-CBC decrypt (IV = first 16 bytes, key from game memory)
    -> PKCS7 unpad
    -> LiteNetLib frame parse (Unreliable / Channeled / Merged)
    -> Game message extraction (uint16 LE message ID + body)
    -> Combat event parsing (SpawnEntity, UpdateHealth, EndCasting, ChatMessage, etc.)
    -> UI display / log output
```

Five background threads: capture engine, connection monitor, key watcher (reads encryption keys from game memory every 5s), packet processor, and the main thread for UI/stats.

## Project Structure

```
mnm.py                  # CLI entry point
parser/parser.py        # GUI entry point (self-contained)
parser/api_client.py    # Optional remote API submission
core/capture.py         # Raw socket capture engine
core/connections.py     # Game connection monitoring (iphlpapi)
core/memory.py          # IL2CPP memory reading (ReadProcessMemory)
core/decrypt.py         # AES-CBC + CRC32c + HMAC decrypt pipeline
core/parser.py          # IP/UDP/TCP + LiteNetLib frame parsing
core/combat.py          # Game message parsing (SpawnEntity, combat events)
core/opcodes.py         # 355 known game message IDs
core/npc_database.py    # NPC spawn data CSV recorder
config.json             # Runtime configuration
```

---

## Protocol Analysis: Scalability Problems

The following documents serious protocol-level issues discovered through reverse-engineering the game's network traffic. These problems would prevent the game from scaling to a large concurrent player base.

### 1. Damage Numbers Only Exist in English Chat Strings

**This is the single biggest design problem in the protocol.**

Melee auto-attack damage is not sent as a structured message. The server composes an English sentence like `"You slash a dunes madman for 52 points of damage."` and transmits it inside a ChatMessage (opcode 0x0040) on channel 1. This chat string is the **only** place the melee damage number exists on the wire.

The companion animation message (0x644B) carries the attacker entity ID, target entity ID, and the verb ("slash", "punch", "stab") -- but **not the damage number**. The information needed for a single melee hit is split across three separate messages:

| Message | Contains | Missing |
|---|---|---|
| UpdateHealth (0x0022) | Target HP delta | Who caused it, damage type |
| ChatMessage (0x0040) | Damage number, English text | Entity IDs |
| 0x644B Animation | Attacker ID, target ID, verb | Damage number |

A structured `MeleeDamage` opcode would be ~14 bytes. The chat string is 40-80+ bytes of UTF-8 text -- 3-6x the bandwidth for the same information. In a 40-player raid with 20 melee attackers swinging once per second, that's 20 unnecessary chat strings per second broadcast to every nearby client.

If the game is ever localized to another language, every client-side damage parser breaks.

### 2. UpdateHealth Has No Attacker Field

`UpdateHealth` is just `[u32 entity_id] [i32 new_hp] [i32 max_hp]` -- 12 bytes. It tells you who lost health and how much, but not who caused it. The client must cross-reference separate BeginCasting, EndCasting, and ChatMessage events (which may arrive out of order over UDP) to figure out damage attribution.

When multiple players attack the same NPC simultaneously, the client receives interleaved messages from different attackers and must maintain a stateful correlation model. Under UDP packet loss (common at scale), attribution becomes impossible to reconstruct.

**Fix:** Add `[u32 source_eid]` and `[u16 ability_id]` to UpdateHealth. One message, all the information.

### 3. Percentage-Based NPC Health

Tougher NPCs report `max_hp=100` in UpdateHealth -- their HP is a percentage, not actual hit points. Meanwhile, the combat text damage numbers are real values (e.g., "252 points of Fire Damage"). The UpdateHealth delta for the same hit might show 3 (percentage points) while the text shows 252 (actual damage).

This forces clients to maintain two parallel damage tracking systems (HP-based and text-based) and pick whichever is higher. Under packet loss, the two systems diverge and neither is reliable.

### 4. 2.9x Encryption Overhead Per Packet

Every UDP datagram is individually encrypted: `[IV(16)] [AES-CBC ciphertext] [CRC32c(4)]`.

An UpdateHealth message (12 bytes payload + 6 bytes framing = 18 bytes) becomes 52 bytes after encryption -- the envelope is **2.9x the payload**. CRC32c integrity checking is redundant when the protocol already supports HMAC (which it leaves empty).

AES-GCM would provide authenticated encryption without a separate CRC or HMAC. Batching multiple game messages into a single encrypted payload (one IV + one CRC for 10 messages) would amortize the fixed overhead.

At 100,000 concurrent players generating 10 packets/second each, the CRC32c computation alone consumes ~1.5 CPU cores.

### 5. No Interest Management on SpawnEntity

SpawnEntity (0x0020) is a massive variable-length packet: entity ID, name, class/race/sex, HP, position, model data, appearance arrays, pet IDs, guild name -- **300-600+ bytes per spawn**. There is no evidence of distance-based visibility culling; all spawns appear to broadcast to every client in the zone.

A zone with 500 NPCs where 10 spawn/despawn per second costs 5-7 KB/sec per client. With 100 clients in a zone, the server uploads 500-700 KB/sec just for spawn broadcasts. Pets and summons that respawn frequently multiply this further.

### 6. SpawnEntity is a Parsing Nightmare

SpawnEntity has no length-prefixed sections, no field count, and no type-length-value encoding. Player and NPC spawns use the same opcode but different byte layouts for the HID string section, with no flag to distinguish them. The sexHID field for NPCs reads as uint16 = 1024 (obviously invalid string length), forcing parsers to abandon sequential reading and brute-force scan for the health stats block.

A single off-by-one in any section corrupts every field that follows. There is no schema versioning -- adding a field in a patch breaks all existing parsers.

### 7. Three Separate Resource Opcodes

Health, mana, and endurance each have their own opcode (0x0022, 0x0023, 0x022F), plus an inconsistently-used combined opcode (0x0027 UpdateHealthMana). When a player loses both HP and mana from one hit, the server sometimes sends two separate messages instead of one.

A single `UpdateResources` opcode with a bitmask for which fields are present would halve the message count for multi-resource events.

### 8. Entity ID Reuse Without Generation Counters

Entity IDs are uint32 and get reused when entities despawn. There is no generation counter or epoch to distinguish "entity #17977 the first dunes madman" from "entity #17977 the second dunes madman that spawned 5 minutes later." Any client-side state cached by entity ID (HP baselines, encounter records, attacker attribution) silently corrupts on reuse.

### 9. Merged Packets Don't Batch by Priority

LiteNetLib's Merged packet type batches sub-messages opportunistically (whatever is in the send queue), not by type or priority. A time-critical UpdateHealth can be bundled with position updates for distant entities and expired buff removals. The client must deserialize the entire merged payload before processing the combat event.

### 10. Session Keys Never Rotate

Encryption keys are provided once at login and stored in game memory for the entire session. They never rotate. If a key is compromised (trivially readable via ReadProcessMemory), all traffic for that session can be decrypted. There is no forward secrecy.

### Summary: Bandwidth Cost Per Melee Hit

| Message | Game payload | Encrypted wire size |
|---|---|---|
| UpdateHealth | ~14 bytes | ~52 bytes |
| ChatMessage (damage text) | ~60 bytes | ~100 bytes |
| 0x644B (animation) | ~23 bytes | ~56 bytes |
| **Total per swing** | **~94 bytes** | **~208 bytes** |

A structured approach (MeleeDamage + UpdateHealth) would deliver the same information in ~30 bytes / ~84 bytes encrypted -- a **60% bandwidth reduction per melee swing**, significant when multiplied across dozens of players in combat.
