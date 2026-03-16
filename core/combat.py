"""
Combat event parser for MnM network traffic.

Watches for combat-relevant game messages and extracts structured events
(damage, healing, abilities, deaths, buffs, etc.) from decoded payloads.

Message body layouts are from IL2CPP dump (dump.cs) + traffic analysis.
"""

import struct
import time
import threading
from collections import defaultdict

from core.opcodes import COMBAT_MSG_IDS, get_message_name


# =========================================================================
# String reading helper (game uses uint16 LE length + UTF-8 bytes)
# =========================================================================

def read_string(data, offset):
    """Read a LiteNetLib length-prefixed string. Length includes trailing null byte.
    Returns (string, new_offset) or (None, offset)."""
    if offset + 2 > len(data):
        return None, offset
    str_len = struct.unpack_from("<H", data, offset)[0]
    offset += 2
    if str_len == 0:
        return "", offset
    if offset + str_len > len(data):
        return None, offset - 2
    raw = data[offset:offset + str_len]
    # Strip trailing null byte (LiteNetLib format includes null in length)
    if raw and raw[-1] == 0:
        s = raw[:-1].decode("utf-8", errors="replace")
    else:
        s = raw.decode("utf-8", errors="replace")
    return s, offset + str_len


def read_uint32(data, offset):
    if offset + 4 > len(data):
        return None, offset
    return struct.unpack_from("<I", data, offset)[0], offset + 4


def read_int32(data, offset):
    if offset + 4 > len(data):
        return None, offset
    return struct.unpack_from("<i", data, offset)[0], offset + 4


def read_uint16(data, offset):
    if offset + 2 > len(data):
        return None, offset
    return struct.unpack_from("<H", data, offset)[0], offset + 2


def read_bool(data, offset):
    if offset + 1 > len(data):
        return None, offset
    return bool(data[offset]), offset + 1


def read_float(data, offset):
    if offset + 4 > len(data):
        return None, offset
    return struct.unpack_from("<f", data, offset)[0], offset + 4


def read_byte(data, offset):
    if offset + 1 > len(data):
        return None, offset
    return data[offset], offset + 1


# =========================================================================
# Parse helpers
# =========================================================================

class _ParseStop(Exception):
    """Raised internally when a read runs out of data during parsing."""
    pass


def _safe_read(reader, data, offset):
    """Wrap a reader; if it returns None, raise _ParseStop."""
    result = reader(data, offset)
    if result[0] is None:
        raise _ParseStop()
    return result


# =========================================================================
# Combat event container
# =========================================================================

class CombatEvent:
    """A single combat-related event extracted from network traffic."""
    __slots__ = ("timestamp", "event_type", "direction", "msg_id", "msg_name",
                 "source_id", "target_id", "fields", "raw_body")

    def __init__(self, event_type, msg_id, direction="IN"):
        self.timestamp = time.time()
        self.event_type = event_type    # "health", "death", "cast", "buff", etc.
        self.direction = direction
        self.msg_id = msg_id
        self.msg_name = get_message_name(msg_id)
        self.source_id = None
        self.target_id = None
        self.fields = {}                # message-specific fields
        self.raw_body = b""

    def format(self):
        """Format as a human-readable combat log line."""
        parts = [f"[{self.msg_name}]"]

        if self.event_type == "health_update":
            hp = self.fields.get("health", "?")
            max_hp = self.fields.get("max_health", "?")
            parts.append(f"Entity#{self.source_id} HP:{hp}/{max_hp}")
            if "mana" in self.fields:
                mp = self.fields.get("mana", "?")
                max_mp = self.fields.get("max_mana", "?")
                parts.append(f"MP:{mp}/{max_mp}")
            if "endurance" in self.fields:
                ep = self.fields.get("endurance", "?")
                max_ep = self.fields.get("max_endurance", "?")
                parts.append(f"END:{ep}/{max_ep}")

        elif self.event_type == "death":
            parts.append(f"Entity#{self.source_id} DIED")
            if self.fields.get("killer_id"):
                parts.append(f"killed by Entity#{self.fields['killer_id']}")
            if self.fields.get("feign"):
                parts.append("(feign)")

        elif self.event_type == "begin_cast":
            name = self.fields.get("ability_name", "?")
            parts.append(f"Entity#{self.source_id} casting [{name}]")
            if self.target_id:
                parts.append(f"-> Entity#{self.target_id}")
            cast_time = self.fields.get("cast_time")
            if cast_time:
                parts.append(f"({cast_time}ms)")

        elif self.event_type == "end_cast":
            parts.append(f"Entity#{self.source_id}")
            if self.target_id:
                parts.append(f"-> Entity#{self.target_id}")
            if self.fields.get("interrupt"):
                parts.append("INTERRUPTED")
            text = self.fields.get("text")
            if text:
                parts.append(f'"{text}"')

        elif self.event_type == "cast_ability":
            gem = self.fields.get("gem_id", "?")
            parts.append(f"CastAbility gem={gem}")
            if self.target_id:
                parts.append(f"-> Entity#{self.target_id}")

        elif self.event_type == "autoattack":
            active = self.fields.get("active", False)
            parts.append(f"Autoattack {'ON' if active else 'OFF'}")

        elif self.event_type == "buff_add":
            parts.append(f"Entity#{self.source_id}")
            name = self.fields.get("buff_name")
            if name:
                parts.append(f"+[{name}]")

        elif self.event_type == "buff_remove":
            parts.append(f"Entity#{self.source_id}")
            buff_id = self.fields.get("entity_buff_id")
            parts.append(f"-buff#{buff_id}")

        elif self.event_type == "stun":
            state = self.fields.get("stunned", False)
            parts.append(f"Entity#{self.source_id} {'STUNNED' if state else 'unstunned'}")

        elif self.event_type == "hostile":
            state = self.fields.get("hostile", False)
            parts.append(f"Entity#{self.source_id} {'HOSTILE' if state else 'non-hostile'}")

        elif self.event_type == "spawn":
            parts.append(f"Entity#{self.source_id}")
            name = self.fields.get("name")
            if name:
                parts.append(f'"{name}"')
            etype = self.fields.get("entity_type")
            if etype is not None:
                parts.append(f"type={etype}")
            lvl = self.fields.get("level")
            if lvl is not None:
                parts.append(f"lv{lvl}")
            hp = self.fields.get("health")
            max_hp = self.fields.get("max_health")
            if hp is not None and max_hp is not None:
                parts.append(f"HP:{hp}/{max_hp}")
            pos_x = self.fields.get("pos_x")
            pos_y = self.fields.get("pos_y")
            pos_z = self.fields.get("pos_z")
            if pos_x is not None:
                parts.append(f"@({pos_x:.1f},{pos_y:.1f},{pos_z:.1f})")
            if self.fields.get("is_hostile"):
                parts.append("HOSTILE")
            guild = self.fields.get("guild_name")
            if guild:
                parts.append(f"<{guild}>")

        elif self.event_type == "despawn":
            parts.append(f"Entity#{self.source_id}")

        elif self.event_type == "target_change":
            parts.append(f"Target -> Entity#{self.target_id}")

        elif self.event_type == "consider":
            parts.append(f"Consider Entity#{self.target_id}")

        elif self.event_type == "particle_hit":
            parts.append(f"-> Entity#{self.target_id}")
            name = self.fields.get("particle_name")
            if name:
                parts.append(f"[{name}]")

        elif self.event_type == "party_update":
            count = self.fields.get("member_count", "?")
            leader = self.fields.get("leader_eid", "?")
            parts.append(f"members={count} leader=#{leader}")
            for m in self.fields.get("members", []):
                eid = m.get("entity_id", "?")
                name = m.get("name", "?")
                cls = m.get("class_hid", "?")
                lvl = m.get("level", "?")
                zone = m.get("zone", "")
                parts.append(f"[#{eid} {name} {cls} L{lvl} {zone}]")

        elif self.event_type == "update_state":
            parts.append(f"Entity#{self.source_id}")
            cls = self.fields.get("class_hid")
            if cls:
                parts.append(f"class={cls}")
            lvl = self.fields.get("level")
            if lvl is not None:
                parts.append(f"L{lvl}")
            blen = self.fields.get("body_len", 0)
            parts.append(f"({blen}B)")
            raw = self.fields.get("raw_hex", "")
            if raw:
                parts.append(f"RAW[{raw[:120]}]")

        elif self.event_type == "update_class":
            parts.append(f"Entity#{self.source_id}")
            cls = self.fields.get("class_hid", "?")
            parts.append(f"class={cls}")
            raw = self.fields.get("raw_hex", "")
            if raw:
                parts.append(f"RAW[{raw[:80]}]")

        elif self.event_type == "update_status":
            parts.append(f"Entity#{self.source_id}")
            blen = self.fields.get("body_len", 0)
            parts.append(f"({blen}B)")
            raw = self.fields.get("raw_hex", "")
            if raw:
                parts.append(f"RAW[{raw[:120]}]")

        elif self.event_type == "chat":
            ch = self.fields.get("channel", "?")
            text = self.fields.get("text", "")
            parts.append(f"ch={ch}")
            if text:
                parts.append(f'"{text[:200]}"')

        elif self.event_type == "update_race_sex":
            parts.append(f"Entity#{self.source_id}")
            race = self.fields.get("race_hid", "?")
            sex = self.fields.get("sex_hid", "?")
            parts.append(f"race={race} sex={sex}")

        elif self.event_type == "update_equipment":
            parts.append(f"Entity#{self.source_id}")
            blen = self.fields.get("body_len", 0)
            parts.append(f"({blen}B)")

        elif self.event_type == "update_name":
            parts.append(f"Entity#{self.source_id}")
            name = self.fields.get("name", "?")
            parts.append(f'name="{name}"')

        elif self.event_type == "update_surname":
            parts.append(f"Entity#{self.source_id}")
            surname = self.fields.get("surname", "?")
            parts.append(f'surname="{surname}"')

        elif self.event_type == "update_guild":
            parts.append(f"Entity#{self.source_id}")
            guild = self.fields.get("guild_name", "?")
            parts.append(f'guild="{guild}"')

        else:
            parts.append(f"src={self.source_id} tgt={self.target_id}")
            if self.fields:
                parts.append(str(self.fields))

        dir_arrow = "<<<" if self.direction == "IN" else ">>>"
        return f"{dir_arrow} {' '.join(parts)}"


# =========================================================================
# Message parsers — one per message type
# =========================================================================

def _parse_update_health(body, direction):
    """UpdateHealth: entity_id(u32) health(i32) maxHealth(i32)"""
    evt = CombatEvent("health_update", 0x0022, direction)
    off = 0
    evt.source_id, off = read_uint32(body, off)
    evt.fields["health"], off = read_int32(body, off)
    evt.fields["max_health"], off = read_int32(body, off)
    return evt


def _parse_update_health_mana(body, direction):
    """UpdateHealthMana: entity_id(u32) health(i32) maxHealth(i32) mana(i32) maxMana(i32)"""
    evt = CombatEvent("health_update", 0x0027, direction)
    off = 0
    evt.source_id, off = read_uint32(body, off)
    evt.fields["health"], off = read_int32(body, off)
    evt.fields["max_health"], off = read_int32(body, off)
    evt.fields["mana"], off = read_int32(body, off)
    evt.fields["max_mana"], off = read_int32(body, off)
    return evt


def _parse_update_mana(body, direction):
    """UpdateMana: entity_id(u32) mana(i32) maxMana(i32)"""
    evt = CombatEvent("health_update", 0x0023, direction)
    off = 0
    evt.source_id, off = read_uint32(body, off)
    evt.fields["mana"], off = read_int32(body, off)
    evt.fields["max_mana"], off = read_int32(body, off)
    return evt


def _parse_update_endurance(body, direction):
    """UpdateEndurance: entity_id(u32) endurance(i32) maxEndurance(i32)"""
    evt = CombatEvent("health_update", 0x022F, direction)
    off = 0
    evt.source_id, off = read_uint32(body, off)
    evt.fields["endurance"], off = read_int32(body, off)
    evt.fields["max_endurance"], off = read_int32(body, off)
    return evt


def _parse_die(body, direction):
    """Die: entity_id(u32) state(bool) killerID(u32) feign(bool)"""
    evt = CombatEvent("death", 0x0013, direction)
    off = 0
    evt.source_id, off = read_uint32(body, off)
    evt.fields["state"], off = read_bool(body, off)
    evt.fields["killer_id"], off = read_uint32(body, off)
    evt.fields["feign"], off = read_bool(body, off)
    return evt


def _parse_begin_casting(body, direction):
    """BeginCasting: id(u32) targetId(u32) abilityName(str) ..."""
    evt = CombatEvent("begin_cast", 0x0055, direction)
    off = 0
    evt.source_id, off = read_uint32(body, off)
    evt.target_id, off = read_uint32(body, off)
    evt.fields["ability_name"], off = read_string(body, off)
    # Try to read remaining known fields
    evt.fields["no_interrupt"], off = read_bool(body, off)
    evt.fields["cast_time"], off = read_uint32(body, off)
    return evt


def _parse_end_casting(body, direction):
    """EndCasting: id(u32) targetId(u32) text(str) ... interruptCasting(bool) ..."""
    evt = CombatEvent("end_cast", 0x0056, direction)
    off = 0
    evt.source_id, off = read_uint32(body, off)
    evt.target_id, off = read_uint32(body, off)
    # text field
    evt.fields["text"], off = read_string(body, off)
    return evt


def _parse_cast_ability(body, direction):
    """CastAbility (client->server): gemID(u16?) targetId(u32?)"""
    evt = CombatEvent("cast_ability", 0x0050, direction)
    off = 0
    # From traffic analysis: appears to be uint16 gemID + uint32 targetId
    evt.fields["gem_id"], off = read_uint16(body, off)
    evt.target_id, off = read_uint32(body, off)
    return evt


def _parse_autoattack(body, direction):
    """Autoattack: active(bool)"""
    evt = CombatEvent("autoattack", 0x0012, direction)
    off = 0
    evt.fields["active"], off = read_bool(body, off)
    return evt


def _parse_add_buff_icon(body, direction):
    """AddBuffIcon: entity_id(u32) BuffRecord(...)"""
    evt = CombatEvent("buff_add", 0x0053, direction)
    off = 0
    evt.source_id, off = read_uint32(body, off)
    # BuffRecord is complex, try to extract the buff name
    # Skip the first u32 (buff index or type)
    _buff_id, off = read_uint32(body, off)
    evt.fields["buff_id"] = _buff_id
    # Try to find a string (buff name)
    evt.fields["buff_name"], off = read_string(body, off)
    return evt


def _parse_remove_buff_icon(body, direction):
    """RemoveBuffIcon: entity_id(u32) entityBuffID(u32)"""
    evt = CombatEvent("buff_remove", 0x0054, direction)
    off = 0
    evt.source_id, off = read_uint32(body, off)
    evt.fields["entity_buff_id"], off = read_uint32(body, off)
    return evt


def _parse_cancel_buff(body, direction):
    """CancelBuff: similar to RemoveBuffIcon"""
    evt = CombatEvent("buff_remove", 0x005D, direction)
    off = 0
    evt.source_id, off = read_uint32(body, off)
    return evt


def _parse_update_stun_state(body, direction):
    """UpdateStunState: entity_id(u32) stunned(bool)"""
    evt = CombatEvent("stun", 0x0029, direction)
    off = 0
    evt.source_id, off = read_uint32(body, off)
    evt.fields["stunned"], off = read_bool(body, off)
    return evt


def _parse_update_hostile_state(body, direction):
    """UpdateHostileState: entity_id(u32) hostile(bool)"""
    evt = CombatEvent("hostile", 0x002A, direction)
    off = 0
    evt.source_id, off = read_uint32(body, off)
    evt.fields["hostile"], off = read_bool(body, off)
    return evt


def _parse_change_target(body, direction):
    """ChangeTarget: targetId(u32)"""
    evt = CombatEvent("target_change", 0x0011, direction)
    off = 0
    evt.target_id, off = read_uint32(body, off)
    return evt


def _parse_consider(body, direction):
    """Consider: targetId(u32)"""
    evt = CombatEvent("consider", 0x0014, direction)
    off = 0
    evt.target_id, off = read_uint32(body, off)
    return evt


# =========================================================================
# SpawnEntity parser — phased with fallback
# =========================================================================

def _find_stats_offset(body, name_end):
    """Scan for the health/maxHealth stats block after the HID region.

    Looks for two consecutive int32 values that are positive and reasonable
    (health and maxHealth), followed by mana (>=0) and maxMana (>0).
    Searches a window after name_end.
    """
    # Primary: try the known 19-byte NPC offset (verified across 4 NPC packets)
    off = name_end + 19
    if off + 16 <= len(body):
        h, mh, mn, mmn = struct.unpack_from("<iiii", body, off)
        if 0 < h <= 1_000_000 and 0 < mh <= 1_000_000 and h <= mh:
            if 0 <= mn <= 1_000_000 and 0 < mmn <= 1_000_000:
                return off

    # Secondary: scan offsets name_end+8 .. name_end+40 for plausible stats
    for delta in range(8, min(41, len(body) - name_end - 15)):
        off = name_end + delta
        if off + 16 > len(body):
            break
        h, mh, mn, mmn = struct.unpack_from("<iiii", body, off)
        if 0 < h <= 1_000_000 and 0 < mh <= 1_000_000 and h <= mh:
            if 0 <= mn <= 1_000_000 and 0 < mmn <= 1_000_000:
                return off

    return None


def _parse_hid_region(body, name_end, stats_off):
    """Try to extract readable HID-like strings from the region between
    name and stats, even when standard string parsing fails."""
    region = body[name_end:stats_off]
    result = {}

    # Extract any short printable ASCII runs (class codes like "bbr", "wlf")
    runs = []
    current = []
    for b in region:
        if 0x20 <= b < 0x7F:
            current.append(b)
        else:
            if current:
                runs.append(bytes(current).decode("ascii"))
                current = []
    if current:
        runs.append(bytes(current).decode("ascii"))

    # Assign runs to fields heuristically
    if runs:
        result["_hid_strings"] = runs
        # First multi-char run is likely classHID code, single-char is sexHID
        for r in runs:
            if len(r) >= 2 and "class_hid" not in result:
                result["class_hid"] = r
            elif len(r) == 1 and "sex_hid" not in result:
                result["sex_hid"] = r

    result["_hid_raw"] = region.hex()
    return result


def _parse_spawn_entity(body, direction):
    """SpawnEntity: phased parse with fallback for the HID string region.

    The wire format between name and health (classHID, raceHID, sexHID,
    skinTone, level) doesn't always parse cleanly with LiteNetLib uint16-len
    strings.  When sequential parsing fails on that section, we fall back to
    scanning for the stats block (health/maxHealth) and continue from there.
    """
    evt = CombatEvent("spawn", 0x0020, direction)
    off = 0
    f = evt.fields

    # ====== Phase 1: Core identity (always works) ======
    try:
        evt.source_id, off = _safe_read(read_uint32, body, off)
        f["entity_type"], off = _safe_read(read_uint16, body, off)
        f["name"], off = _safe_read(read_string, body, off)
    except _ParseStop:
        f["_parsed_bytes"] = off
        return evt

    name_end = off

    # ====== Phase 2: HID strings + skinTone + level ======
    # Try sequential parsing first; fall back to scan if it fails.
    # The sexHID field fails for NPC packets because bytes at that offset
    # produce uint16 LE = 1024 (not a valid string length).
    hid_ok = False
    try:
        f["class_hid"], off = _safe_read(read_string, body, off)
        f["race_hid"], off = _safe_read(read_string, body, off)
        f["sex_hid"], off = _safe_read(read_string, body, off)
        f["skin_tone"], off = _safe_read(read_uint16, body, off)
        f["level"], off = _safe_read(read_int32, body, off)
        hid_ok = True
    except _ParseStop:
        pass

    if not hid_ok:
        # Scan ahead for the stats block (health/maxHealth)
        stats_off = _find_stats_offset(body, name_end)
        if stats_off is None:
            f["_parsed_bytes"] = name_end
            if name_end < len(body):
                f["raw_tail"] = body[name_end:].hex()
            return evt

        # Extract what we can from the HID region via ASCII scanning
        hid_data = _parse_hid_region(body, name_end, stats_off)
        f.update(hid_data)
        off = stats_off

    # ====== Phase 3: Stats ======
    try:
        f["health"], off = _safe_read(read_int32, body, off)
        f["max_health"], off = _safe_read(read_int32, body, off)
        f["mana"], off = _safe_read(read_int32, body, off)
        f["max_mana"], off = _safe_read(read_int32, body, off)
    except _ParseStop:
        f["_parsed_bytes"] = off
        return evt

    # ====== Phase 4: PositionSyncGoalData ======
    try:
        f["pos_tick"], off = _safe_read(read_uint32, body, off)
        pos_flags, off = _safe_read(read_byte, body, off)
        f["pos_flags"] = pos_flags

        if pos_flags & 0x01:  # has position data
            f["pos_x"], off = _safe_read(read_float, body, off)
            f["pos_y"], off = _safe_read(read_float, body, off)
            f["pos_z"], off = _safe_read(read_float, body, off)
            f["facing"], off = _safe_read(read_float, body, off)
            f["_pos_unk2"], off = _safe_read(read_uint16, body, off)
            f["extrap_x"], off = _safe_read(read_float, body, off)
            f["extrap_y"], off = _safe_read(read_float, body, off)
            f["extrap_z"], off = _safe_read(read_float, body, off)
            f["_extrap_tail"], off = _safe_read(read_uint16, body, off)
    except _ParseStop:
        f["_parsed_bytes"] = off
        return evt

    # ====== Phase 5: Boolean flags + combat state ======
    try:
        f["is_attacking"], off = _safe_read(read_bool, body, off)
        f["target_id"], off = _safe_read(read_uint32, body, off)
        evt.target_id = f["target_id"] if f["target_id"] else None
        f["is_sitting"], off = _safe_read(read_bool, body, off)
        f["is_corpse"], off = _safe_read(read_bool, body, off)
        f["is_corpse_mine"], off = _safe_read(read_bool, body, off)
        f["is_hostile"], off = _safe_read(read_bool, body, off)
        f["is_stealth"], off = _safe_read(read_bool, body, off)
        f["can_see"], off = _safe_read(read_bool, body, off)
        f["hide_nameplate"], off = _safe_read(read_bool, body, off)
    except _ParseStop:
        f["_parsed_bytes"] = off
        return evt

    # ====== Phase 6: Model data ======
    try:
        f["model_size"], off = _safe_read(read_float, body, off)
        f["master_id"], off = _safe_read(read_uint32, body, off)
        f["is_player_pet"], off = _safe_read(read_bool, body, off)
        f["no_collision"], off = _safe_read(read_bool, body, off)
        f["light"], off = _safe_read(read_int32, body, off)
        # lightColor: 4 floats (RGBA)
        f["light_r"], off = _safe_read(read_float, body, off)
        f["light_g"], off = _safe_read(read_float, body, off)
        f["light_b"], off = _safe_read(read_float, body, off)
        f["light_a"], off = _safe_read(read_float, body, off)
        f["animation_preset_id"], off = _safe_read(read_byte, body, off)
        f["show_ranged_weapon"], off = _safe_read(read_bool, body, off)
    except _ParseStop:
        f["_parsed_bytes"] = off
        return evt

    # ====== Phase 7: Appearance arrays (variable-length) ======
    try:
        # attachmentDefinitions[]
        attach_count, off = _safe_read(read_uint32, body, off)
        f["attachment_count"] = attach_count

        # textureDefinitions[]
        tex_count, off = _safe_read(read_uint32, body, off)
        f["texture_count"] = tex_count
        textures = []
        for _ in range(min(tex_count, 32)):
            tex_id, off = _safe_read(read_byte, body, off)
            tex_hid, off = _safe_read(read_string, body, off)
            lerp_hid1, off = _safe_read(read_string, body, off)
            lerp_hid2, off = _safe_read(read_string, body, off)
            lerp_hid3, off = _safe_read(read_string, body, off)
            tex_color, off = _safe_read(read_uint16, body, off)
            tex_value, off = _safe_read(read_float, body, off)
            textures.append(tex_hid)
        f["textures"] = textures

        # features[]
        feat_count, off = _safe_read(read_uint32, body, off)
        f["feature_count"] = feat_count
        for _ in range(min(feat_count, 32)):
            _feat_hid, off = _safe_read(read_string, body, off)
            _feat_feature, off = _safe_read(read_uint16, body, off)
            _feat_color, off = _safe_read(read_uint16, body, off)
            _feat_custom_color, off = _safe_read(read_uint32, body, off)
            _feat_enable_custom, off = _safe_read(read_bool, body, off)

        # materialOverride(str), modelOverride(str)
        f["material_override"], off = _safe_read(read_string, body, off)
        f["model_override"], off = _safe_read(read_string, body, off)

        # pets[] (uint32 array)
        pet_count, off = _safe_read(read_uint32, body, off)
        f["pet_count"] = pet_count
        for _ in range(min(pet_count, 16)):
            _pet_id, off = _safe_read(read_uint32, body, off)

        # serverTime(f32)
        f["server_time"], off = _safe_read(read_float, body, off)

        # anonymousType(enum as byte)
        f["anonymous_type"], off = _safe_read(read_byte, body, off)

        # Trailing booleans and strings
        f["is_hardcore"], off = _safe_read(read_bool, body, off)
        f["is_lfg"], off = _safe_read(read_bool, body, off)
        f["surname"], off = _safe_read(read_string, body, off)
        f["guild_name"], off = _safe_read(read_string, body, off)
        f["guild_rank"], off = _safe_read(read_byte, body, off)
        f["has_gm_nametag"], off = _safe_read(read_bool, body, off)
        f["is_self_found"], off = _safe_read(read_bool, body, off)
        f["is_pvp_flagged"], off = _safe_read(read_bool, body, off)

        # deityHIDList[]
        deity_count, off = _safe_read(read_uint32, body, off)
        f["deity_count"] = deity_count
        deities = []
        for _ in range(min(deity_count, 16)):
            d, off = _safe_read(read_string, body, off)
            deities.append(d)
        f["deities"] = deities

    except _ParseStop:
        pass

    # Store how far we parsed and any remaining raw bytes
    f["_parsed_bytes"] = off
    if off < len(body):
        f["raw_tail"] = body[off:].hex()

    return evt


def _parse_despawn_entity(body, direction):
    """DespawnEntity: entity_id(u32)"""
    evt = CombatEvent("despawn", 0x0021, direction)
    off = 0
    evt.source_id, off = read_uint32(body, off)
    return evt


# =========================================================================
# Group/class/level discovery parsers (for /reload analysis)
# =========================================================================

def _parse_client_party_update(body, direction):
    """ClientPartyUpdate (0x0380): Party member list with class/level/zone.
    Wire format (verified):
      member_count: u32
      per member:
        entity_id:   u32
        unknown_u32: u32  (secondary id)
        name:        LNL string
        class_hid:   LNL string  (e.g. "dru", "pal", "war", "wiz")
        level:       u8
        zone:        LNL string
      leader_eid:    u32  (party leader entity id)
    """
    evt = CombatEvent("party_update", 0x0380, direction)
    off = 0
    f = evt.fields
    try:
        member_count, off = _safe_read(read_uint32, body, off)
        f["member_count"] = member_count
        members = []
        for i in range(min(member_count, 12)):
            m = {}
            m["entity_id"], off = _safe_read(read_uint32, body, off)
            m["unknown_id"], off = _safe_read(read_uint32, body, off)
            m["name"], off = _safe_read(read_string, body, off)
            m["class_hid"], off = _safe_read(read_string, body, off)
            m["level"], off = _safe_read(read_byte, body, off)
            m["zone"], off = _safe_read(read_string, body, off)
            members.append(m)
        f["members"] = members
        f["leader_eid"], off = _safe_read(read_uint32, body, off)
    except _ParseStop:
        f["_parsed_bytes"] = off
    return evt


def _parse_update_state(body, direction):
    """UpdateState (0x002F): Full player state resync. Dump for analysis."""
    evt = CombatEvent("update_state", 0x002F, direction)
    off = 0
    f = evt.fields
    try:
        evt.source_id, off = _safe_read(read_uint32, body, off)
        # Try reading common fields - structure unknown, dump everything
        f["class_hid"], off = _safe_read(read_string, body, off)
        f["level"], off = _safe_read(read_int32, body, off)
    except _ParseStop:
        f["_parsed_bytes"] = off
    f["raw_hex"] = body.hex(' ')
    f["body_len"] = len(body)
    return evt


def _parse_update_class_hid(body, direction):
    """UpdateClassHID (0x005F): Class change notification."""
    evt = CombatEvent("update_class", 0x005F, direction)
    off = 0
    f = evt.fields
    try:
        evt.source_id, off = _safe_read(read_uint32, body, off)
        f["class_hid"], off = _safe_read(read_string, body, off)
    except _ParseStop:
        f["_parsed_bytes"] = off
    f["raw_hex"] = body.hex(' ')
    return evt


def _parse_update_status(body, direction):
    """UpdateStatus (0x013F): Status update. Dump for analysis."""
    evt = CombatEvent("update_status", 0x013F, direction)
    off = 0
    f = evt.fields
    try:
        evt.source_id, off = _safe_read(read_uint32, body, off)
    except _ParseStop:
        pass
    f["raw_hex"] = body.hex(' ')
    f["body_len"] = len(body)
    return evt


def _parse_chat_message(body, direction):
    """ChatMessage (0x0040): Chat with channel. Log for /reload context."""
    evt = CombatEvent("chat", 0x0040, direction)
    off = 0
    f = evt.fields
    try:
        f["channel"], off = _safe_read(read_uint32, body, off)
        f["text"], off = _safe_read(read_string, body, off)
    except _ParseStop:
        f["_parsed_bytes"] = off
    return evt


def _parse_update_race_sex(body, direction):
    """UpdateRaceSex (0x0038): Race/sex change."""
    evt = CombatEvent("update_race_sex", 0x0038, direction)
    off = 0
    f = evt.fields
    try:
        evt.source_id, off = _safe_read(read_uint32, body, off)
        f["race_hid"], off = _safe_read(read_string, body, off)
        f["sex_hid"], off = _safe_read(read_string, body, off)
    except _ParseStop:
        f["_parsed_bytes"] = off
    f["raw_hex"] = body.hex(' ')
    return evt


def _parse_update_equipment(body, direction):
    """UpdateEquipment (0x0083): Equipment update. Dump for analysis."""
    evt = CombatEvent("update_equipment", 0x0083, direction)
    off = 0
    f = evt.fields
    try:
        evt.source_id, off = _safe_read(read_uint32, body, off)
    except _ParseStop:
        pass
    f["raw_hex"] = body.hex(' ')
    f["body_len"] = len(body)
    return evt


def _parse_update_name(body, direction):
    """UpdateName (0x008A): Name update."""
    evt = CombatEvent("update_name", 0x008A, direction)
    off = 0
    f = evt.fields
    try:
        evt.source_id, off = _safe_read(read_uint32, body, off)
        f["name"], off = _safe_read(read_string, body, off)
    except _ParseStop:
        f["_parsed_bytes"] = off
    f["raw_hex"] = body.hex(' ')
    return evt


def _parse_update_surname(body, direction):
    """UpdateSurname (0x0084): Surname update."""
    evt = CombatEvent("update_surname", 0x0084, direction)
    off = 0
    f = evt.fields
    try:
        evt.source_id, off = _safe_read(read_uint32, body, off)
        f["surname"], off = _safe_read(read_string, body, off)
    except _ParseStop:
        f["_parsed_bytes"] = off
    f["raw_hex"] = body.hex(' ')
    return evt


def _parse_update_guild_info(body, direction):
    """UpdateGuildInfo (0x008E): Guild info update."""
    evt = CombatEvent("update_guild", 0x008E, direction)
    off = 0
    f = evt.fields
    try:
        evt.source_id, off = _safe_read(read_uint32, body, off)
        f["guild_name"], off = _safe_read(read_string, body, off)
    except _ParseStop:
        f["_parsed_bytes"] = off
    f["raw_hex"] = body.hex(' ')
    return evt


def _parse_particle_hit(body, direction):
    """ParticleHit: targetId(u32) hitParticleName(str)"""
    evt = CombatEvent("particle_hit", 0x005C, direction)
    off = 0
    evt.target_id, off = read_uint32(body, off)
    evt.fields["particle_name"], off = read_string(body, off)
    return evt


def _parse_channel_ability(body, direction):
    """ChannelAbility"""
    evt = CombatEvent("begin_cast", 0x0146, direction)
    off = 0
    evt.source_id, off = read_uint32(body, off)
    evt.target_id, off = read_uint32(body, off)
    evt.fields["ability_name"], off = read_string(body, off)
    return evt


# Map of msg_id -> parser function
_PARSERS = {
    0x0022: _parse_update_health,
    0x0027: _parse_update_health_mana,
    0x0023: _parse_update_mana,
    0x022F: _parse_update_endurance,
    0x0013: _parse_die,
    0x0055: _parse_begin_casting,
    0x0056: _parse_end_casting,
    0x0050: _parse_cast_ability,
    0x0012: _parse_autoattack,
    0x0053: _parse_add_buff_icon,
    0x0054: _parse_remove_buff_icon,
    0x005D: _parse_cancel_buff,
    0x0029: _parse_update_stun_state,
    0x002A: _parse_update_hostile_state,
    0x0011: _parse_change_target,
    0x0014: _parse_consider,
    0x0020: _parse_spawn_entity,
    0x0021: _parse_despawn_entity,
    0x005C: _parse_particle_hit,
    0x0146: _parse_channel_ability,
    # Group/class/level discovery
    0x0380: _parse_client_party_update,
    0x002F: _parse_update_state,
    0x005F: _parse_update_class_hid,
    0x013F: _parse_update_status,
    0x0040: _parse_chat_message,
    0x0038: _parse_update_race_sex,
    0x0083: _parse_update_equipment,
    0x008A: _parse_update_name,
    0x0084: _parse_update_surname,
    0x008E: _parse_update_guild_info,
}


# =========================================================================
# CombatParser — main class
# =========================================================================

class CombatParser:
    """
    Processes decoded game messages and emits combat events.

    Usage:
        parser = CombatParser()
        for msg in game_messages:
            event = parser.process(msg, direction)
            if event:
                print(event.format())
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._event_count = 0
        self._event_counts = defaultdict(int)  # event_type -> count
        self._entity_names = {}  # entity_id -> name (from SpawnEntity)
        self._entity_health = {}  # entity_id -> (hp, max_hp)

    @property
    def stats(self):
        with self._lock:
            return {
                "total_events": self._event_count,
                "by_type": dict(self._event_counts),
                "tracked_entities": len(self._entity_names),
            }

    def get_entity_name(self, entity_id):
        """Look up entity name from SpawnEntity tracking."""
        return self._entity_names.get(entity_id)

    def process(self, game_msg, direction="IN"):
        """
        Process a GameMessage and return a CombatEvent if combat-relevant.
        Returns None for non-combat messages.
        """
        if game_msg.msg_id not in COMBAT_MSG_IDS:
            return None

        parser_fn = _PARSERS.get(game_msg.msg_id)
        if parser_fn is None:
            # Known combat message but no specific parser yet
            evt = CombatEvent("combat", game_msg.msg_id, direction)
            evt.raw_body = game_msg.body
            return evt

        try:
            evt = parser_fn(game_msg.body, direction)
        except Exception:
            # Parse error — return a basic event with raw body
            evt = CombatEvent("parse_error", game_msg.msg_id, direction)
            evt.raw_body = game_msg.body
            return evt

        evt.raw_body = game_msg.body

        # Track entity names from SpawnEntity
        if evt.event_type == "spawn" and evt.source_id and evt.fields.get("name"):
            with self._lock:
                self._entity_names[evt.source_id] = evt.fields["name"]

        # Track health values
        if evt.event_type == "health_update" and evt.source_id:
            hp = evt.fields.get("health")
            max_hp = evt.fields.get("max_health")
            if hp is not None and max_hp is not None:
                with self._lock:
                    self._entity_health[evt.source_id] = (hp, max_hp)

        with self._lock:
            self._event_count += 1
            self._event_counts[evt.event_type] += 1

        return evt

    def format_with_names(self, event):
        """Format event, substituting entity IDs with names where known."""
        text = event.format()
        with self._lock:
            for eid, name in self._entity_names.items():
                text = text.replace(f"Entity#{eid}", f"{name}(#{eid})")
        return text

    def get_summary(self):
        """Return a summary of combat activity."""
        with self._lock:
            if self._event_count == 0:
                return "No combat events recorded"
            lines = [f"=== Combat Summary ({self._event_count} events) ==="]
            for etype, count in sorted(self._event_counts.items(),
                                       key=lambda x: -x[1]):
                lines.append(f"  {etype}: {count}")
            if self._entity_names:
                lines.append(f"\n  Tracked entities: {len(self._entity_names)}")
                for eid, name in sorted(self._entity_names.items()):
                    hp_info = ""
                    if eid in self._entity_health:
                        hp, max_hp = self._entity_health[eid]
                        hp_info = f" HP:{hp}/{max_hp}"
                    lines.append(f"    #{eid}: {name}{hp_info}")
            return "\n".join(lines)
