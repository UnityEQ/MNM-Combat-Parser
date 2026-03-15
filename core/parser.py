"""
Layered packet parser: IP → UDP/TCP → LiteNetLib → Game messages.

Protocol stack (after AES decryption):
  UDP payload → LiteNetLib frame → Game messages (2-byte LE message ID)

LiteNetLib Merged frames contain nested LNL sub-frames (usually Unreliable)
that must be recursively parsed to reach the game-level payload.

Game message wire format: [msg_id (uint16 LE)] [message body]
"""

import struct
import threading
import time
from collections import namedtuple

from core.opcodes import get_message_name, is_combat_message


# ===== Legacy compatibility =====

PacketInfo = namedtuple("PacketInfo", [
    "timestamp", "direction", "protocol",
    "src_ip", "src_port", "dst_ip", "dst_port",
    "payload", "positions",
])


# ===========================================================================
# IP / UDP / TCP Headers
# ===========================================================================

def parse_ip_header(data):
    """Parse IPv4 header. Returns (protocol, src_ip, dst_ip, ihl, total_len) or None."""
    if len(data) < 20:
        return None
    version_ihl = data[0]
    if (version_ihl >> 4) != 4:
        return None
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    total_length = struct.unpack("!H", data[2:4])[0]
    protocol = data[9]
    src_ip = f"{data[12]}.{data[13]}.{data[14]}.{data[15]}"
    dst_ip = f"{data[16]}.{data[17]}.{data[18]}.{data[19]}"
    return protocol, src_ip, dst_ip, ihl, total_length


def parse_udp_header(data):
    """Parse UDP header. Returns (src_port, dst_port, payload) or None."""
    if len(data) < 8:
        return None
    src_port, dst_port, length = struct.unpack("!HHH", data[0:6])
    payload = data[8:length] if length > 8 else b""
    return src_port, dst_port, payload


def parse_tcp_header(data):
    """Parse TCP header. Returns (src_port, dst_port, payload) or None."""
    if len(data) < 20:
        return None
    src_port, dst_port = struct.unpack("!HH", data[0:4])
    data_offset = (data[12] >> 4) * 4
    if data_offset < 20 or len(data) < data_offset:
        return None
    return src_port, dst_port, data[data_offset:]


# ===========================================================================
# LiteNetLib Frame Parser (Layer 1)
# ===========================================================================
#
# LiteNetLib first byte layout:
#   Bits 0-4: PacketProperty (0-17)
#   Bits 5-6: ConnectionNumber (0-3)
#   Bit 7:    IsFragmented
#
# Enum values from game IL2CPP dump (LiteNetLib.PacketProperty).

PACKET_PROPERTIES = {
    0:  "Unreliable",
    1:  "Channeled",
    2:  "Ack",
    3:  "Ping",
    4:  "Pong",
    5:  "ConnectRequest",
    6:  "ConnectAccept",
    7:  "Disconnect",
    8:  "UnconnectedMessage",
    9:  "MtuCheck",
    10: "MtuOk",
    11: "Broadcast",
    12: "Merged",
    13: "ShutdownOk",
    14: "PeerNotFound",
    15: "InvalidProtocol",
    16: "NatMessage",
    17: "Empty",
}


class LiteNetLibFrame:
    __slots__ = ("packet_property", "property_name", "connection_number",
                 "is_fragmented", "sequence", "channel",
                 "fragment_id", "fragment_part", "fragment_total",
                 "inner_payloads", "is_control")

    def __init__(self):
        self.packet_property = 0
        self.property_name = "Unknown"
        self.connection_number = 0
        self.is_fragmented = False
        self.sequence = None
        self.channel = None
        self.fragment_id = None
        self.fragment_part = None
        self.fragment_total = None
        self.inner_payloads = []
        self.is_control = False


def parse_litenetlib_frame(payload):
    """
    Attempt to parse a LiteNetLib transport frame.

    Data-bearing types: 0 (Unreliable), 1 (Channeled), 12 (Merged).
    Control types: 2-11, 13-17 (Ack, Ping, Pong, Connect*, Disconnect, etc.)
    Values > 17 are treated as unknown — the entire payload (minus byte 0)
    is returned as a single inner payload for empirical analysis.
    """
    if not payload:
        return None

    frame = LiteNetLibFrame()
    byte0 = payload[0]

    frame.packet_property = byte0 & 0x1F
    frame.connection_number = (byte0 >> 5) & 0x03
    frame.is_fragmented = bool(byte0 & 0x80)
    frame.property_name = PACKET_PROPERTIES.get(frame.packet_property,
                                                 f"Type_{frame.packet_property}")

    prop = frame.packet_property

    # Control types — no game data
    if prop in (2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 16, 17):
        frame.is_control = True
        frame.inner_payloads = []
        return frame

    # Unreliable (type 0): 1-byte header
    if prop == 0:
        header_size = 1
        if frame.is_fragmented and len(payload) >= 7:
            frame.fragment_id = struct.unpack_from("<H", payload, 1)[0]
            frame.fragment_part = struct.unpack_from("<H", payload, 3)[0]
            frame.fragment_total = struct.unpack_from("<H", payload, 5)[0]
            header_size = 7
        elif frame.is_fragmented:
            header_size = 1  # can't read fragment header, skip it
        if len(payload) > header_size:
            frame.inner_payloads = [payload[header_size:]]
        return frame

    # Channeled (type 1): 4-byte header [type, seq_lo, seq_hi, channel]
    if prop == 1:
        if len(payload) < 4:
            return frame
        frame.sequence = payload[1] | (payload[2] << 8)
        frame.channel = payload[3]
        header_size = 4
        if frame.is_fragmented and len(payload) >= 10:
            frame.fragment_id = struct.unpack_from("<H", payload, 4)[0]
            frame.fragment_part = struct.unpack_from("<H", payload, 6)[0]
            frame.fragment_total = struct.unpack_from("<H", payload, 8)[0]
            header_size = 10
        elif frame.is_fragmented:
            header_size = 4
        if len(payload) > header_size:
            frame.inner_payloads = [payload[header_size:]]
        return frame

    # Merged (type 12): 1-byte header + batched messages
    if prop == 12:
        frame.inner_payloads = _unbatch_merged(payload[1:])
        return frame

    # Unknown property (> 18): treat entire payload after byte 0 as raw data
    if len(payload) > 1:
        frame.inner_payloads = [payload[1:]]
    return frame


def _unbatch_merged(data):
    """Extract individual messages from [LE uint16 length][data]... format."""
    messages = []
    offset = 0
    while offset + 2 <= len(data):
        msg_len = struct.unpack_from("<H", data, offset)[0]
        offset += 2
        if msg_len == 0 or offset + msg_len > len(data):
            break
        messages.append(data[offset:offset + msg_len])
        offset += msg_len
    return messages


# ===========================================================================
# Float Triplet Scanner
# ===========================================================================

def scan_float_triplets(data, range_min=-50000.0, range_max=50000.0,
                        magnitude_threshold=0.5):
    """
    Scan for Vector3 float triplets.

    - Skips 12 bytes after each match (no overlapping)
    - Requires abs(x)+abs(y)+abs(z) > magnitude_threshold
    - Requires at least 2 of 3 components to be non-trivial (> 0.1)
      to filter noise where only one component has a value
    """
    results = []
    if len(data) < 12:
        return results

    i = 0
    while i <= len(data) - 12:
        try:
            x, y, z = struct.unpack_from("<fff", data, i)
        except struct.error:
            i += 1
            continue

        if not (_is_plausible(x, range_min, range_max) and
                _is_plausible(y, range_min, range_max) and
                _is_plausible(z, range_min, range_max)):
            i += 1
            continue

        if abs(x) + abs(y) + abs(z) <= magnitude_threshold:
            i += 1
            continue

        # Require at least 2 non-trivial components — single-axis values
        # are almost always false positives from random byte patterns
        nontrivial = (abs(x) > 0.1) + (abs(y) > 0.1) + (abs(z) > 0.1)
        if nontrivial < 2:
            i += 1
            continue

        results.append((i, x, y, z))
        i += 12

    return results


def _is_plausible(val, range_min, range_max):
    if val != val:
        return False
    if val == float("inf") or val == float("-inf"):
        return False
    return range_min <= val <= range_max


# ===========================================================================
# Byte Distribution Tracker (for reverse-engineering)
# ===========================================================================

class ByteTracker:
    """
    Track distribution of first N bytes across MATCHED game packets,
    split by direction (IN/OUT), to identify the actual protocol framing.
    Also cross-tabulates byte[0] x packet size for pattern detection.
    """

    def __init__(self, track_bytes=8):
        self._track_bytes = track_bytes
        self._lock = threading.Lock()
        # Per-direction stats
        self._dirs = {}  # direction -> {total, size_counts, byte_counts, byte0_size}

    def _get_dir(self, direction):
        if direction not in self._dirs:
            self._dirs[direction] = {
                "total": 0,
                "size_counts": {},
                "byte_counts": [{} for _ in range(self._track_bytes)],
                "byte0_size": {},  # (byte0, size) -> count
            }
        return self._dirs[direction]

    def record(self, payload, direction):
        with self._lock:
            d = self._get_dir(direction)
            d["total"] += 1
            size = len(payload)
            d["size_counts"][size] = d["size_counts"].get(size, 0) + 1
            for i in range(min(self._track_bytes, len(payload))):
                b = payload[i]
                d["byte_counts"][i][b] = d["byte_counts"][i].get(b, 0) + 1
            if payload:
                key = (payload[0], size)
                d["byte0_size"][key] = d["byte0_size"].get(key, 0) + 1

    def get_report(self):
        """Generate a human-readable analysis of byte distributions per direction."""
        with self._lock:
            total_all = sum(d["total"] for d in self._dirs.values())
            if total_all == 0:
                return "No game packets recorded"

            lines = [f"=== Protocol Analysis ({total_all} game packets) ==="]

            for direction in sorted(self._dirs.keys()):
                d = self._dirs[direction]
                total = d["total"]
                if total == 0:
                    continue

                label = "SERVER->CLIENT" if direction == "IN" else "CLIENT->SERVER"
                lines.append(f"\n--- {label} ({total} packets) ---")

                # Size distribution
                sizes = sorted(d["size_counts"].items(), key=lambda x: -x[1])
                lines.append(f"\n  Top packet sizes:")
                for size, count in sizes[:10]:
                    pct = count * 100 / total
                    lines.append(f"    {size:5d} bytes: {count:5d} ({pct:5.1f}%)")

                # Byte position analysis
                for pos in range(self._track_bytes):
                    counts = d["byte_counts"][pos]
                    if not counts:
                        continue
                    unique = len(counts)
                    top = sorted(counts.items(), key=lambda x: -x[1])[:8]
                    lines.append(f"\n  Byte[{pos}]: {unique} unique values")
                    for val, count in top:
                        pct = count * 100 / total
                        lines.append(
                            f"    0x{val:02X} ({val:3d}): {count:5d} ({pct:5.1f}%)"
                        )

                # Byte[0] x Size cross-tabulation (top combos)
                b0s = sorted(d["byte0_size"].items(), key=lambda x: -x[1])
                lines.append(f"\n  Top byte[0] x size combos:")
                for (b0, sz), count in b0s[:12]:
                    pct = count * 100 / total
                    lines.append(
                        f"    byte0=0x{b0:02X} size={sz:5d}: {count:5d} ({pct:5.1f}%)"
                    )

            return "\n".join(lines)


# ===========================================================================
# Full Packet Parse Pipeline
# ===========================================================================

class ParsedPacket:
    __slots__ = ("timestamp", "direction", "protocol",
                 "src_ip", "src_port", "dst_ip", "dst_port",
                 "raw_payload", "litenetlib_frame", "fishnet_messages",
                 "positions", "parse_errors", "byte0", "hex_preview",
                 "encrypted_blocks")

    def __init__(self):
        self.timestamp = 0.0
        self.direction = "UNK"
        self.protocol = ""
        self.src_ip = ""
        self.src_port = 0
        self.dst_ip = ""
        self.dst_port = 0
        self.raw_payload = b""
        self.litenetlib_frame = None
        self.fishnet_messages = []
        self.positions = []
        self.parse_errors = []
        self.byte0 = 0
        self.hex_preview = ""
        self.encrypted_blocks = 0  # (payload_len - 4) / 16 if AES


class GameMessage:
    """A decoded game-level message with 2-byte uint16 LE message ID."""
    __slots__ = ("msg_id", "msg_name", "body", "raw_data",
                 "lnl_type", "sequence", "channel")

    def __init__(self, msg_id, body, raw_data, lnl_type="Unreliable",
                 sequence=None, channel=None):
        self.msg_id = msg_id
        self.msg_name = get_message_name(msg_id)
        self.body = body          # message body after 2-byte ID
        self.raw_data = raw_data  # full inner payload including ID
        self.lnl_type = lnl_type
        self.sequence = sequence
        self.channel = channel


def extract_game_messages(plaintext):
    """
    Full pipeline: decrypted plaintext → LiteNetLib frame → game messages.

    For Merged frames, recursively parses nested LNL sub-frames.
    Returns (LiteNetLibFrame, list[GameMessage]).
    """
    frame = parse_litenetlib_frame(plaintext)
    if frame is None:
        return None, []

    if frame.is_control:
        return frame, []

    messages = []

    if frame.packet_property == 12:  # Merged
        # Each sub-message is a nested LNL frame
        for sub_payload in frame.inner_payloads:
            if len(sub_payload) < 1:
                continue
            sub_frame = parse_litenetlib_frame(sub_payload)
            if sub_frame is None or sub_frame.is_control:
                continue
            for inner in sub_frame.inner_payloads:
                msg = _parse_game_message(inner, sub_frame.property_name,
                                          sub_frame.sequence, sub_frame.channel)
                if msg:
                    messages.append(msg)
    else:
        # Unreliable / Channeled — inner payloads are game messages directly
        for inner in frame.inner_payloads:
            msg = _parse_game_message(inner, frame.property_name,
                                      frame.sequence, frame.channel)
            if msg:
                messages.append(msg)

    return frame, messages


def _parse_game_message(data, lnl_type="Unreliable", sequence=None, channel=None):
    """Parse a game message from inner payload: [msg_id (uint16 LE)] [body]."""
    if len(data) < 2:
        return None
    msg_id = struct.unpack_from("<H", data, 0)[0]
    body = data[2:]
    return GameMessage(msg_id, body, data, lnl_type, sequence, channel)


# Legacy alias
class FishNetMessage:
    __slots__ = ("opcode", "opcode_name", "raw_data", "body",
                 "entity_id", "positions")

    def __init__(self, opcode, raw_data, body):
        self.opcode = opcode
        self.opcode_name = f"0x{opcode:02X}"
        self.raw_data = raw_data
        self.body = body
        self.entity_id = None
        self.positions = []


def parse_packet_v2(raw_data, direction="UNK",
                    range_min=-50000.0, range_max=50000.0,
                    magnitude_threshold=0.5):
    """
    Full parse pipeline: IP → UDP/TCP → frame analysis → position scan.
    """
    ip = parse_ip_header(raw_data)
    if ip is None:
        return None
    protocol_num, src_ip, dst_ip, ip_hdr_len, total_len = ip
    transport_data = raw_data[ip_hdr_len:]

    if protocol_num == 17:
        result = parse_udp_header(transport_data)
        if result is None:
            return None
        src_port, dst_port, payload = result
        protocol = "UDP"
    elif protocol_num == 6:
        result = parse_tcp_header(transport_data)
        if result is None:
            return None
        src_port, dst_port, payload = result
        protocol = "TCP"
    else:
        return None

    pkt = ParsedPacket()
    pkt.timestamp = time.time()
    pkt.direction = direction
    pkt.protocol = protocol
    pkt.src_ip = src_ip
    pkt.src_port = src_port
    pkt.dst_ip = dst_ip
    pkt.dst_port = dst_port
    pkt.raw_payload = payload

    if not payload:
        return pkt

    pkt.byte0 = payload[0]
    pkt.hex_preview = " ".join(f"{b:02x}" for b in payload[:16])

    # Wire format: [IV(16)] [AES ciphertext(N*16)] [CRC32c(4)]
    payload_len = len(payload)
    if payload_len >= 36 and (payload_len - 4) % 16 == 0:
        pkt.encrypted_blocks = (payload_len - 20) // 16

    return pkt


# ===========================================================================
# Legacy compatibility
# ===========================================================================

def get_opcode_name(opcode):
    return get_message_name(opcode)


class OpcodeTracker:
    """Stub for backward compat — replaced by ByteTracker."""
    def __init__(self):
        pass
    def record(self, *args):
        pass
    def get_summary(self):
        return []
    def dump_unknown(self, logger):
        pass


def parse_fishnet_header(payload):
    if len(payload) < 4:
        return None
    length = struct.unpack_from("<H", payload, 0)[0]
    channel = payload[2]
    opcode = payload[3]
    if length > len(payload) + 10 or length < 2:
        return None
    return length, channel, opcode, payload[4:]


def parse_packet(raw_data, direction="UNK", range_min=-50000.0, range_max=50000.0):
    pkt = parse_packet_v2(raw_data, direction, range_min=range_min,
                          range_max=range_max)
    if pkt is None:
        return None
    return PacketInfo(
        timestamp=pkt.timestamp, direction=pkt.direction, protocol=pkt.protocol,
        src_ip=pkt.src_ip, src_port=pkt.src_port,
        dst_ip=pkt.dst_ip, dst_port=pkt.dst_port,
        payload=pkt.raw_payload, positions=pkt.positions,
    )
