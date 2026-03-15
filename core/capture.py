"""
Raw socket packet capture engine using SIO_RCVALL on Windows.
"""

import queue
import socket
import struct
import threading

from core.logger import get_logger


def get_local_ip():
    """Auto-detect the primary local IP address."""
    try:
        # Connect to a public DNS to determine which interface is used
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "0.0.0.0"


class CaptureEngine:
    """
    Raw socket capture engine.

    Binds to the local interface, enables promiscuous mode (SIO_RCVALL),
    and pushes raw packet data into a thread-safe queue.
    """

    def __init__(self, interface_ip="auto", packet_queue=None):
        self._interface_ip = interface_ip if interface_ip != "auto" else get_local_ip()
        self._queue = packet_queue or queue.Queue(maxsize=10000)
        self._sock = None
        self._thread = None
        self._stop_event = threading.Event()
        self._packets_captured = 0
        self._bytes_captured = 0

    @property
    def packet_queue(self):
        return self._queue

    @property
    def stats(self):
        return {
            "packets": self._packets_captured,
            "bytes": self._bytes_captured,
        }

    def start(self):
        """Create raw socket, enable promiscuous mode, and start capture thread."""
        log = get_logger()

        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                        socket.IPPROTO_IP)
            self._sock.bind((self._interface_ip, 0))

            # Include IP headers
            self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            # Enable promiscuous mode
            self._sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

            log.info(f"Capture engine started on {self._interface_ip}")
        except PermissionError:
            log.error("Raw socket creation failed — run as Administrator!")
            raise
        except OSError as e:
            log.error(f"Socket error: {e}")
            raise

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._recv_loop, daemon=True,
                                         name="CaptureEngine")
        self._thread.start()

    def stop(self):
        """Disable promiscuous mode and close socket."""
        log = get_logger()
        self._stop_event.set()

        if self._sock:
            try:
                self._sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None

        log.info(f"Capture engine stopped — {self._packets_captured} packets, "
                 f"{self._bytes_captured} bytes")

    def _recv_loop(self):
        """Main receive loop running in a dedicated thread."""
        log = get_logger()
        buf_size = 65535

        while not self._stop_event.is_set():
            try:
                self._sock.settimeout(1.0)
                data = self._sock.recvfrom(buf_size)
                raw = data[0]

                self._packets_captured += 1
                self._bytes_captured += len(raw)

                try:
                    self._queue.put_nowait(raw)
                except queue.Full:
                    # Drop oldest packet to make room
                    try:
                        self._queue.get_nowait()
                    except queue.Empty:
                        pass
                    self._queue.put_nowait(raw)

            except socket.timeout:
                continue
            except OSError as e:
                if self._stop_event.is_set():
                    break
                log.warning(f"Capture recv error: {e}")
                continue
            except Exception as e:
                if self._stop_event.is_set():
                    break
                log.error(f"Capture thread error: {e}")
                break
