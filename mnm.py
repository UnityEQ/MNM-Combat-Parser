"""
MNM Network Traffic Capture Tool
=================================
Captures and analyzes network traffic from the Unity MMO game process.
Requires Administrator privileges on Windows.

Usage:
    python mnm.py [--process NAME] [--interface IP] [--log-level LEVEL]
"""

import argparse
import ctypes
import json
import os
import queue
import signal
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.logger import setup_logging, get_logger, log_packet, log_hex_dump, log_console
from core.process import find_game_pid, wait_for_process, is_process_alive
from core.connections import ConnectionMonitor
from core.capture import CaptureEngine
from core.parser import parse_packet_v2, ByteTracker, parse_litenetlib_frame, extract_game_messages
from core.opcodes import get_message_name
from core.combat import CombatParser
from core.memory import KeyWatcher, read_encryption_keys
from core.decrypt import PacketDecryptor
from core.npc_database import NpcDatabase


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def load_config(path="config.json"):
    defaults = {
        "process_name": "mnm.exe",
        "interface_ip": "auto",
        "connection_refresh_seconds": 5,
        "log_level": "INFO",
        "log_hex_dump": True,
        "position_range_min": -50000.0,
        "position_range_max": 50000.0,
        "magnitude_threshold": 0.5,
        "protocol_analysis_interval": 60,
        "capture_filter": {
            "protocols": ["UDP", "TCP"],
            "exclude_ports": [80, 443, 53]
        }
    }
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), path)
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                user_config = json.load(f)
            defaults.update(user_config)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: Could not load {path}: {e} — using defaults")
    return defaults


def parse_args():
    parser = argparse.ArgumentParser(description="MNM Network Traffic Capture Tool")
    parser.add_argument("--process", "-p", type=str, default=None)
    parser.add_argument("--interface", "-i", type=str, default=None)
    parser.add_argument("--log-level", "-l", type=str, default=None,
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument("--no-wait", action="store_true")
    parser.add_argument("--dump-keys", action="store_true",
                        help="Read encryption keys from game memory and exit")
    return parser.parse_args()


class PacketProcessor:
    """
    Pulls packets from the capture queue, parses them, filters by game
    connections, decrypts when keys are available, and logs traffic analysis.
    """

    def __init__(self, packet_queue, conn_monitor, config, key_watcher=None,
                 npc_db=None):
        self._queue = packet_queue
        self._conn_monitor = conn_monitor
        self._config = config
        self._key_watcher = key_watcher
        self._npc_db = npc_db
        self._stop_event = threading.Event()
        self._thread = None
        self._processed = 0
        self._matched = 0
        self._decrypted = 0
        self._decrypt_failures = 0
        self._bytes_in = 0
        self._bytes_out = 0
        self._packets_in = 0
        self._packets_out = 0
        self._allowed_protocols = set(
            p.upper() for p in config.get("capture_filter", {}).get("protocols", ["UDP", "TCP"])
        )
        self._log_hex = config.get("log_hex_dump", True)
        self._byte_tracker = ByteTracker(track_bytes=8)
        self._analysis_interval = config.get("protocol_analysis_interval", 60)
        # Rate tracking (per-second snapshots)
        self._rate_window = []  # list of (timestamp, direction, size)
        self._last_rate_log = 0.0
        # Decryption
        self._decryptor = None
        self._last_aes_key = None  # Track key changes
        # Combat parser
        self._combat_parser = CombatParser()
        self._combat_log_interval = config.get("combat_log_interval", 60)

    @property
    def stats(self):
        return {
            "processed": self._processed,
            "matched": self._matched,
            "decrypted": self._decrypted,
            "decrypt_failures": self._decrypt_failures,
            "packets_in": self._packets_in,
            "packets_out": self._packets_out,
            "bytes_in": self._bytes_in,
            "bytes_out": self._bytes_out,
            "combat_events": self._combat_parser.stats["total_events"],
        }

    @property
    def combat_parser(self):
        return self._combat_parser

    @property
    def byte_tracker(self):
        return self._byte_tracker

    def start(self):
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._process_loop, daemon=True,
                                         name="PacketProcessor")
        self._thread.start()
        get_logger().info("Packet processor started")

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)

    def _process_loop(self):
        log = get_logger()
        last_analysis = time.time()

        while not self._stop_event.is_set():
            try:
                raw = self._queue.get(timeout=0.5)
            except queue.Empty:
                now = time.time()
                if now - last_analysis >= self._analysis_interval:
                    self._log_protocol_analysis(log)
                    last_analysis = now
                continue

            self._processed += 1

            pkt = parse_packet_v2(raw)
            if pkt is None:
                continue

            if pkt.protocol not in self._allowed_protocols:
                continue

            if not self._conn_monitor.matches_game_traffic(
                    pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port):
                continue

            self._matched += 1

            direction = self._conn_monitor.get_direction(
                pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)
            pkt.direction = direction

            payload_len = len(pkt.raw_payload)
            if direction == "IN":
                self._packets_in += 1
                self._bytes_in += payload_len
            else:
                self._packets_out += 1
                self._bytes_out += payload_len

            # Track byte distributions for matched game packets only
            if pkt.raw_payload:
                self._byte_tracker.record(pkt.raw_payload, direction)

            # Track rate window (keep last 10 seconds)
            now = pkt.timestamp
            self._rate_window.append((now, direction, payload_len))
            cutoff = now - 10.0
            while self._rate_window and self._rate_window[0][0] < cutoff:
                self._rate_window.pop(0)

            # Attempt decryption if keys are available
            plaintext = self._try_decrypt(pkt, log)

            self._log_packet(log, pkt, plaintext)

    def _try_decrypt(self, pkt, log):
        """Attempt to decrypt the packet payload. Returns plaintext or None."""
        if not self._key_watcher or not self._key_watcher.has_keys:
            return None
        if not pkt.raw_payload or len(pkt.raw_payload) < 36:
            return None

        # Create or recreate decryptor when keys change
        keys = self._key_watcher.keys
        aes_key = keys.get("aes_key")
        if not aes_key:
            return None

        if self._decryptor is None or aes_key != self._last_aes_key:
            hmac_key = keys.get("hmac_key")
            xor_key = keys.get("xor_key")
            self._decryptor = PacketDecryptor(aes_key, hmac_key, xor_key)
            self._last_aes_key = aes_key
            log.info("Decryptor initialized (CRC+AES-CBC+PKCS7)")

        plaintext, info = self._decryptor.decrypt(pkt.raw_payload)
        if plaintext:
            self._decrypted += 1
            return plaintext
        else:
            # CRC failure = not a game packet (port collision), don't count
            if info.get("crc_verified") is not False:
                self._decrypt_failures += 1
            return None

    def _log_packet(self, log, pkt, plaintext=None):
        src = f"{pkt.src_ip}:{pkt.src_port}"
        dst = f"{pkt.dst_ip}:{pkt.dst_port}"

        blocks = f" AES:{pkt.encrypted_blocks}blk" if pkt.encrypted_blocks else ""

        extra = f"[{pkt.hex_preview}]{blocks}"

        # If decrypted, parse LiteNetLib frame and extract game messages
        if plaintext:
            frame, game_msgs = extract_game_messages(plaintext)
            if frame:
                frame_info = f" LNL[{frame.property_name}"
                if frame.sequence is not None:
                    frame_info += f" seq={frame.sequence}"
                if frame.channel is not None:
                    frame_info += f" ch={frame.channel}"
                if game_msgs:
                    frame_info += f" msgs={len(game_msgs)}"
                frame_info += "]"
                extra += frame_info

                # Log game messages with 2-byte IDs, names, and body hex
                for msg in game_msgs:
                    body_hex = msg.body.hex(' ')
                    extra += f" MSG[0x{msg.msg_id:04X}={msg.msg_name} len={len(msg.body)} body={body_hex}]"

            # Log decrypted hex preview
            pt_preview = " ".join(f"{b:02x}" for b in plaintext[:24])
            extra += f" PT[{pt_preview}]"

            # Process combat events
            for msg in game_msgs:
                evt = self._combat_parser.process(msg, pkt.direction)
                if evt:
                    combat_line = self._combat_parser.format_with_names(evt)
                    log_console(log, combat_line)
                    # Record spawn events to NPC database
                    if evt.event_type == "spawn" and self._npc_db:
                        self._npc_db.record(evt)

        # File only (DEBUG)
        log_packet(log, pkt.direction, pkt.protocol, src, dst,
                   len(pkt.raw_payload), extra)

        if self._log_hex and pkt.raw_payload:
            log_hex_dump(log, pkt.raw_payload, prefix=f"{pkt.direction} ")
        if self._log_hex and plaintext:
            log_hex_dump(log, plaintext, prefix=f"{pkt.direction} PT ")

    def _log_protocol_analysis(self, log):
        report = self._byte_tracker.get_report()

        # Add rate summary
        now = time.time()
        window = [r for r in self._rate_window if r[0] >= now - 10.0]
        if window:
            span = max(now - window[0][0], 1.0)
            in_pkts = sum(1 for _, d, _ in window if d == "IN")
            out_pkts = sum(1 for _, d, _ in window if d == "OUT")
            in_bytes = sum(s for _, d, s in window if d == "IN")
            out_bytes = sum(s for _, d, s in window if d == "OUT")
            rate_info = (
                f"\n--- Traffic Rate (last {span:.0f}s) ---"
                f"\n  IN:  {in_pkts/span:.1f} pkt/s, {in_bytes/span/1024:.1f} KB/s"
                f"\n  OUT: {out_pkts/span:.1f} pkt/s, {out_bytes/span/1024:.1f} KB/s"
            )
            report += rate_info

        log.info("\n" + report)


def print_banner():
    print("=" * 60)
    print("  MNM Network Traffic Capture Tool")
    print("  Captures game network traffic for analysis")
    print("=" * 60)
    print()


def main():
    print_banner()

    if not is_admin():
        print("ERROR: This tool requires Administrator privileges.")
        print("Right-click and 'Run as administrator', or use an elevated shell.")
        sys.exit(1)

    config = load_config()
    args = parse_args()

    process_name = args.process or config["process_name"]
    interface_ip = args.interface or config["interface_ip"]
    log_level = args.log_level or config["log_level"]

    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    logger = setup_logging(log_dir=log_dir, log_level=log_level)

    logger.info(f"Configuration: process={process_name}, interface={interface_ip}, "
                f"log_level={log_level}")

    if args.no_wait:
        pid = find_game_pid(process_name)
        if pid is None:
            logger.error(f"Process '{process_name}' not found. Exiting.")
            sys.exit(1)
    else:
        pid = wait_for_process(process_name)

    logger.info(f"Attached to {process_name} (PID {pid})")

    # --dump-keys: read encryption keys and exit
    if args.dump_keys:
        print(f"\nReading encryption keys from PID {pid}...")
        try:
            keys = read_encryption_keys(pid)
            print()
            for name, val in keys.items():
                if val:
                    print(f"  {name}: ({len(val)} bytes) {val.hex()}")
                else:
                    print(f"  {name}: not set (game may not be connected to a server)")
            if not any(keys.values()):
                print("\n  No keys found. Make sure you're logged into a game server.")
        except Exception as e:
            print(f"\n  ERROR: {e}")
        sys.exit(0)

    exclude_ports = config.get("capture_filter", {}).get("exclude_ports", [])
    refresh_interval = config.get("connection_refresh_seconds", 5)

    conn_monitor = ConnectionMonitor(pid, refresh_interval=refresh_interval,
                                      exclude_ports=exclude_ports)
    capture = CaptureEngine(interface_ip=interface_ip)
    key_watcher = KeyWatcher(pid, poll_interval=5.0)
    npc_db = NpcDatabase()
    logger.info(f"NPC database: {npc_db._csv_path}")
    processor = PacketProcessor(capture.packet_queue, conn_monitor, config,
                                key_watcher=key_watcher, npc_db=npc_db)

    shutdown_event = threading.Event()

    def shutdown(signum=None, frame=None):
        if shutdown_event.is_set():
            return
        shutdown_event.set()
        logger.info("Shutting down...")
        processor.stop()
        capture.stop()
        key_watcher.stop()
        conn_monitor.stop()

        cap_stats = capture.stats
        proc_stats = processor.stats
        logger.info(
            f"Final stats: {cap_stats['packets']} captured, "
            f"{proc_stats['matched']} matched game "
            f"(IN:{proc_stats['packets_in']} OUT:{proc_stats['packets_out']}), "
            f"traffic: {proc_stats['bytes_in']/1024:.1f}KB in / "
            f"{proc_stats['bytes_out']/1024:.1f}KB out"
        )

        # Dump protocol analysis
        processor._log_protocol_analysis(logger)

        # Dump combat summary
        combat_summary = processor.combat_parser.get_summary()
        logger.info("\n" + combat_summary)

        # Dump NPC database summary
        logger.info(npc_db.get_summary())

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        conn_monitor.start()
        key_watcher.start()
        capture.start()
        processor.start()
    except Exception as e:
        logger.error(f"Failed to start: {e}")
        import traceback
        traceback.print_exc()
        shutdown()
        sys.exit(1)

    logger.info("Capture running — press Ctrl+C to stop")

    stats_interval = 10
    last_stats = time.time()

    try:
        while not shutdown_event.is_set():
            if not is_process_alive(pid):
                logger.warning(f"{process_name} (PID {pid}) has exited")
                break

            now = time.time()
            if now - last_stats >= stats_interval:
                cap_stats = capture.stats
                proc_stats = processor.stats
                conns = conn_monitor.get_connections()
                key_status = "keys:YES" if key_watcher.has_keys else "keys:NO"
                combat_events = proc_stats.get("combat_events", 0)
                logger.info(
                    f"Stats: {proc_stats['matched']} game pkts "
                    f"(IN:{proc_stats['packets_in']} OUT:{proc_stats['packets_out']}), "
                    f"{proc_stats['bytes_in']/1024:.1f}KB in / "
                    f"{proc_stats['bytes_out']/1024:.1f}KB out, "
                    f"{len(conns)} conns, {key_status}, "
                    f"combat:{combat_events}"
                )
                last_stats = now

            time.sleep(1)

    except KeyboardInterrupt:
        pass
    finally:
        shutdown()

    print("\nDone.")


if __name__ == "__main__":
    main()
