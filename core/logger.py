"""
Dual-output logging: colored console + rotating file log.
"""

import logging
import os
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler


# ANSI color codes for console output
class _Colors:
    RESET = "\033[0m"
    GREEN = "\033[32m"      # Inbound packets
    RED = "\033[31m"        # Outbound packets
    YELLOW = "\033[33m"     # Warnings
    CYAN = "\033[36m"       # Info / status
    WHITE = "\033[37m"      # Debug
    BOLD = "\033[1m"
    DIM = "\033[2m"


# Enable ANSI escape sequences on Windows 10+
def _enable_ansi():
    if sys.platform == "win32":
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # STD_OUTPUT_HANDLE = -11
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_ulong()
        kernel32.GetConsoleMode(handle, ctypes.byref(mode))
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        kernel32.SetConsoleMode(handle, mode.value | 0x0004)


class ColoredFormatter(logging.Formatter):
    """Console formatter with ANSI colors based on log level and packet direction."""

    LEVEL_COLORS = {
        logging.DEBUG: _Colors.WHITE,
        logging.INFO: _Colors.CYAN,
        logging.WARNING: _Colors.YELLOW,
        logging.ERROR: _Colors.RED,
        logging.CRITICAL: _Colors.BOLD + _Colors.RED,
    }

    def format(self, record):
        color = self.LEVEL_COLORS.get(record.levelno, _Colors.RESET)

        # Special coloring for packet direction markers
        msg = super().format(record)
        if hasattr(record, "direction"):
            if record.direction == "IN":
                color = _Colors.GREEN
            elif record.direction == "OUT":
                color = _Colors.RED

        # Strip control characters that cause console beeps/noise
        msg = msg.replace("\a", "").replace("\x07", "")

        return f"{color}{msg}{_Colors.RESET}"


class PacketAdapter(logging.LoggerAdapter):
    """Logger adapter that adds packet direction to log records."""

    def process(self, msg, kwargs):
        extra = kwargs.get("extra", {})
        extra.update(self.extra)
        kwargs["extra"] = extra
        return msg, kwargs


def setup_logging(log_dir="logs", log_level="INFO", console=True):
    """
    Configure dual logging (console + file).

    Returns the root logger for the application.
    """
    _enable_ansi()

    log_dir = os.path.abspath(log_dir)
    os.makedirs(log_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"mnm_{timestamp}.log")

    logger = logging.getLogger("mnm")
    logger.setLevel(logging.DEBUG)  # Let file handler capture everything
    logger.handlers.clear()

    # File handler — full detail including hex dumps, 10 MB rotation, keep 5 backups
    file_fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-5s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    fh = RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=20)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(file_fmt)
    logger.addHandler(fh)

    # Console handler — colored, condensed
    if console:
        console_fmt = ColoredFormatter(
            "%(asctime)s [%(levelname)-5s] %(message)s",
            datefmt="%H:%M:%S"
        )
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(getattr(logging, log_level.upper(), logging.INFO))
        ch.setFormatter(console_fmt)
        logger.addHandler(ch)

    logger.info(f"Logging initialized — file: {log_file}")
    return logger


def get_logger():
    """Get the application logger (must call setup_logging first)."""
    return logging.getLogger("mnm")


def log_packet(logger, direction, protocol, src, dst, size, extra_msg=""):
    """Log a packet to file only (DEBUG level). Use log_console() for console output."""
    arrow = "<<<" if direction == "IN" else ">>>"
    msg = f"{arrow} {protocol} {src} -> {dst} ({size} bytes)"
    if extra_msg:
        msg += f" | {extra_msg}"
    logger.debug(msg, extra={"direction": direction})


def log_console(logger, msg):
    """Log a message to both console and file (INFO level)."""
    logger.info(msg)


def log_hex_dump(logger, data, prefix=""):
    """Log a hex dump of raw bytes at DEBUG level."""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {prefix}{i:04x}: {hex_part:<48s} {ascii_part}")
    logger.debug("\n".join(lines))
