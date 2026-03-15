"""
MNM Combat Parser — API Client

Background thread that batches and sends combat data, loot events, items,
and NPC info to the centralized website API.

Stdlib only: urllib.request, threading, hmac, json.
"""

import hashlib
import hmac
import json
import logging
import threading
import time
import urllib.error
import urllib.request

_log = logging.getLogger("parser_debug")


class ApiClient:
    """Thread-safe API client that batches and sends data periodically."""

    def __init__(self, api_url, api_key, batch_interval=15):
        self._url = api_url.rstrip('/')
        self._key = api_key
        self._interval = max(5, batch_interval)
        self._stop = threading.Event()
        self._thread = None

        # Thread-safe queues
        self._lock = threading.Lock()
        self._combat_queue = []
        self._loot_queue = []
        self._item_cache = {}    # hid -> item dict (dedup)
        self._npc_cache = {}     # (name, class, level) -> npc dict (dedup)

        # Queue limits
        self._max_combat = 500
        self._max_loot = 200

        # Status
        self._last_status = ""
        self._status_lock = threading.Lock()

    @property
    def status(self):
        with self._status_lock:
            return self._last_status

    def _set_status(self, msg):
        with self._status_lock:
            self._last_status = msg

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._send_loop, daemon=True, name="ApiClient")
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    # --- Public queue methods ---

    def queue_combat_event(self, event):
        """Queue a combat event dict for sending."""
        with self._lock:
            if len(self._combat_queue) < self._max_combat:
                self._combat_queue.append(event)

    def queue_loot_event(self, event):
        """Queue a loot event dict for sending."""
        with self._lock:
            if len(self._loot_queue) < self._max_loot:
                self._loot_queue.append(event)

    def queue_item(self, item):
        """Queue an item dict for sending (deduped by hid)."""
        hid = item.get("hid")
        if not hid:
            return
        with self._lock:
            self._item_cache[hid] = item

    def queue_npc(self, npc):
        """Queue an NPC dict for sending (deduped by name+class+level)."""
        key = (npc.get("entity_name", ""), npc.get("class_hid", ""), npc.get("level"))
        with self._lock:
            self._npc_cache[key] = npc

    # --- Background sender ---

    def _send_loop(self):
        while not self._stop.is_set():
            self._stop.wait(self._interval)
            if self._stop.is_set():
                break
            self._flush()
        # Final flush on shutdown
        self._flush()

    def _flush(self):
        """Drain queues and send a batch to the API."""
        with self._lock:
            combat = list(self._combat_queue)
            loot = list(self._loot_queue)
            items = list(self._item_cache.values())
            npcs = list(self._npc_cache.values())
            self._combat_queue.clear()
            self._loot_queue.clear()
            self._item_cache.clear()
            self._npc_cache.clear()

        if not combat and not loot and not items and not npcs:
            return

        payload = {"version": 1}
        if combat:
            payload["combat_events"] = combat
        if loot:
            payload["loot_events"] = loot
        if items:
            payload["items"] = items
        if npcs:
            payload["npcs"] = npcs

        body = json.dumps(payload, separators=(',', ':'))
        success = False

        for attempt in range(3):
            try:
                self._send_request(body)
                total = len(combat) + len(loot) + len(items) + len(npcs)
                self._set_status(f"API: sent {total} records")
                _log.debug(f"API batch sent: {len(combat)}c {len(loot)}l {len(items)}i {len(npcs)}n")
                success = True
                break
            except urllib.error.HTTPError as e:
                msg = f"API HTTP {e.code}"
                try:
                    resp = json.loads(e.read().decode())
                    msg += f": {resp.get('error', '')}"
                except Exception:
                    pass
                self._set_status(msg)
                _log.warning(f"API send failed (attempt {attempt+1}): {msg}")
                if e.code in (401, 403, 400):
                    break  # don't retry auth/validation errors
            except Exception as e:
                self._set_status(f"API error: {e}")
                _log.warning(f"API send failed (attempt {attempt+1}): {e}")

            if attempt < 2:
                time.sleep(2 ** attempt)

        if not success:
            _log.warning("API batch dropped after retries")

    def _send_request(self, body):
        """Send an HMAC-signed POST request."""
        timestamp = str(int(time.time()))
        signature = hmac.new(
            self._key.encode('utf-8'),
            (timestamp + ':' + body).encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        req = urllib.request.Request(
            self._url,
            data=body.encode('utf-8'),
            method='POST',
            headers={
                'Content-Type': 'application/json',
                'X-API-Key': self._key,
                'X-API-Timestamp': timestamp,
                'X-API-Signature': signature,
            },
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read()
