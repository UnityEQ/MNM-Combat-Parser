"""
NPC Database — persists SpawnEntity data to CSV for building an NPC database
over time from captured network traffic.

Each SpawnEntity event appends a row (no deduplication — same NPC may spawn
at different locations across sessions).
"""

import csv
import os
import threading
import time


# CSV column order
_COLUMNS = [
    "timestamp", "entity_id", "entity_type", "name",
    "class_hid", "race_hid", "sex_hid", "skin_tone", "level",
    "health", "max_health", "mana", "max_mana",
    "pos_x", "pos_y", "pos_z", "facing",
    "model_size", "is_hostile", "is_attacking", "target_id",
    "is_corpse", "is_sitting", "master_id", "is_player_pet",
    "guild_name", "guild_rank", "surname",
    "is_hardcore", "is_pvp_flagged", "server_time",
    "textures", "raw_hex",
]


class NpcDatabase:
    """Thread-safe CSV-backed NPC database built from SpawnEntity events."""

    def __init__(self, csv_path=None):
        if csv_path is None:
            base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            csv_path = os.path.join(base, "data", "npc_database.csv")
        self._csv_path = csv_path
        self._lock = threading.Lock()
        self._count = 0
        self._seen = set()  # (entity_id, name) pairs already in CSV
        self._ensure_dir()
        self._write_header_if_new()
        self._load_existing()

    def _ensure_dir(self):
        d = os.path.dirname(self._csv_path)
        if d and not os.path.exists(d):
            os.makedirs(d, exist_ok=True)

    def _write_header_if_new(self):
        if not os.path.exists(self._csv_path):
            with open(self._csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(_COLUMNS)

    def _load_existing(self):
        """Load (entity_id, name) pairs from existing CSV to avoid duplicates."""
        if not os.path.exists(self._csv_path):
            return
        try:
            with open(self._csv_path, "r", newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    eid = row.get("entity_id", "")
                    name = row.get("name", "")
                    if eid and name:
                        self._seen.add((eid, name))
        except (IOError, csv.Error):
            pass

    def record(self, combat_event):
        """Record a SpawnEntity CombatEvent to the CSV database."""
        if combat_event.event_type != "spawn":
            return
        f = combat_event.fields

        # Deduplicate by (entity_id, name)
        key = (str(combat_event.source_id), f.get("name", ""))

        row = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S",
                                       time.localtime(combat_event.timestamp)),
            "entity_id": combat_event.source_id,
            "entity_type": f.get("entity_type", ""),
            "name": f.get("name", ""),
            "class_hid": f.get("class_hid", ""),
            "race_hid": f.get("race_hid", ""),
            "sex_hid": f.get("sex_hid", ""),
            "skin_tone": f.get("skin_tone", ""),
            "level": f.get("level", ""),
            "health": f.get("health", ""),
            "max_health": f.get("max_health", ""),
            "mana": f.get("mana", ""),
            "max_mana": f.get("max_mana", ""),
            "pos_x": _fmt_float(f.get("pos_x")),
            "pos_y": _fmt_float(f.get("pos_y")),
            "pos_z": _fmt_float(f.get("pos_z")),
            "facing": _fmt_float(f.get("facing")),
            "model_size": _fmt_float(f.get("model_size")),
            "is_hostile": _fmt_bool(f.get("is_hostile")),
            "is_attacking": _fmt_bool(f.get("is_attacking")),
            "target_id": f.get("target_id", ""),
            "is_corpse": _fmt_bool(f.get("is_corpse")),
            "is_sitting": _fmt_bool(f.get("is_sitting")),
            "master_id": f.get("master_id", ""),
            "is_player_pet": _fmt_bool(f.get("is_player_pet")),
            "guild_name": f.get("guild_name", ""),
            "guild_rank": f.get("guild_rank", ""),
            "surname": f.get("surname", ""),
            "is_hardcore": _fmt_bool(f.get("is_hardcore")),
            "is_pvp_flagged": _fmt_bool(f.get("is_pvp_flagged")),
            "server_time": _fmt_float(f.get("server_time")),
            "textures": ";".join(f.get("textures", [])),
            "raw_hex": combat_event.raw_body.hex() if combat_event.raw_body else "",
        }

        with self._lock:
            if key in self._seen:
                return
            self._seen.add(key)
            try:
                with open(self._csv_path, "a", newline="", encoding="utf-8") as fp:
                    writer = csv.writer(fp)
                    writer.writerow([row.get(c, "") for c in _COLUMNS])
                self._count += 1
            except IOError:
                pass  # Don't crash capture on write failure

    @property
    def count(self):
        with self._lock:
            return self._count

    def get_summary(self):
        """Return a summary of the NPC database."""
        with self._lock:
            if self._count == 0:
                return (f"NPC Database: no new entities this session "
                        f"({len(self._seen)} unique in DB)")
            return (f"NPC Database: {self._count} new entities this session "
                    f"({len(self._seen)} unique total) -> {self._csv_path}")


def _fmt_float(val):
    if val is None:
        return ""
    return f"{val:.2f}"


def _fmt_bool(val):
    if val is None:
        return ""
    return "1" if val else "0"
