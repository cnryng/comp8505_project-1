#!/usr/bin/env python3
"""
File Watcher using inotify (Linux)
Monitors a directory for file system events in real time.

Requirements:
    sudo pip install inotify

Usage:
    python file_watcher.py [directory]
    python file_watcher.py /tmp
"""

import sys
import os
import time
import logging

try:
    import inotify.adapters
    import inotify.constants
except ImportError:
    print("inotify package not found. Install it with: pip install inotify")
    sys.exit(1)

# ── Logging setup ────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("file_watcher")

# ── Human-readable event names ───────────────────────────────────────────────

EVENT_LABELS = {
    "IN_CREATE":        "Created",
    "IN_DELETE":        "Deleted",
    "IN_MODIFY":        "Modified",
    "IN_MOVED_FROM":    "Moved from",
    "IN_MOVED_TO":      "Moved to",
    "IN_CLOSE_WRITE":   "Closed (write)",
    "IN_OPEN":          "Opened",
    "IN_ACCESS":        "Accessed",
    "IN_ATTRIB":        "Attributes changed",
    "IN_DELETE_SELF":   "Watch target deleted",
    "IN_MOVE_SELF":     "Watch target moved",
}

# ── Core watcher ─────────────────────────────────────────────────────────────

class FileWatcher:
    """
    Watch a directory (and optionally its subdirectories) for inotify events.

    Parameters
    ----------
    path        : directory to watch
    recursive   : whether to watch subdirectories automatically
    event_mask  : inotify event flags to listen for (default: all common events)
    ignore_exts : set of file extensions to ignore, e.g. {'.swp', '.tmp'}
    """

    DEFAULT_MASK = (
        inotify.constants.IN_CREATE
        | inotify.constants.IN_DELETE
        | inotify.constants.IN_MODIFY
        | inotify.constants.IN_MOVED_FROM
        | inotify.constants.IN_MOVED_TO
        | inotify.constants.IN_CLOSE_WRITE
        | inotify.constants.IN_ATTRIB
    )

    def __init__(
        self,
        path: str,
        recursive: bool = True,
        event_mask: int | None = None,
        ignore_exts: set[str] | None = None,
    ):
        path = os.path.abspath(os.path.expanduser(path))

        if os.path.isfile(path):
            self.target_file = os.path.basename(path)
            self.path = os.path.dirname(path)
            self.recursive = False  # no point recursing for a single file
        elif os.path.isdir(path):
            self.target_file = None
            self.path = path
            self.recursive = recursive
        else:
            raise ValueError(f"Path does not exist: {path}")

        self.event_mask = event_mask or self.DEFAULT_MASK
        self.ignore_exts = ignore_exts or {".swp", ".swx", "~"}

        self.changed_dir = os.path.join(os.getcwd(), "changed_files")
        os.makedirs(self.changed_dir, exist_ok=True)

        self._stats = {"total": 0, "by_type": {}}
        self._start_time = None

    # ── Public API ────────────────────────────────────────────────────────────

    def watch(self) -> None:
        """Block and process events until interrupted."""
        adapter_cls = (
            inotify.adapters.InotifyTree if self.recursive
            else inotify.adapters.Inotify
        )

        log.info("Starting file watcher")
        if self.target_file:
            log.info("  File      : %s", os.path.join(self.path, self.target_file))
        else:
            log.info("  Directory : %s", self.path)
            log.info("  Recursive : %s", self.recursive)
        log.info("  Staging   : %s", self.changed_dir)
        log.info("Press Ctrl+C to stop.\n")

        self._start_time = time.monotonic()

        try:
            if self.recursive:
                i = inotify.adapters.InotifyTree(self.path, mask=self.event_mask)
            else:
                i = inotify.adapters.Inotify()
                i.add_watch(self.path, mask=self.event_mask)

            for event in i.event_gen(yield_nones=False):
                _, type_names, watch_path, filename = event
                self._handle(type_names, watch_path, filename)

        except KeyboardInterrupt:
            self._print_summary()

    # ── Internals ─────────────────────────────────────────────────────────────

    def _handle(self, type_names: list[str], watch_path: str, filename: str) -> None:
        """Process a single inotify event."""
        # If watching a single file, ignore events for other files
        if self.target_file and filename != self.target_file:
            return

        # Skip hidden files / swap files / undesired extensions
        if filename:
            _, ext = os.path.splitext(filename)
            if ext in self.ignore_exts or filename.startswith("."):
                return

        full_path = os.path.join(watch_path, filename) if filename else watch_path
        # Make path relative for readability
        try:
            display_path = os.path.relpath(full_path, start=os.path.dirname(self.path))
        except ValueError:
            display_path = full_path

        for event_name in type_names:
            label = EVENT_LABELS.get(event_name, event_name)
            log.info("%-22s  %s", label, display_path)

            # Copy modified/moved files into changed_files/; remove on delete
            if filename and event_name in ("IN_CLOSE_WRITE", "IN_MOVED_TO"):
                # Always copy from the canonical watched path, not the event's
                # reported path, which may be a temp file name (e.g. shadow+)
                # in atomic-rename workflows.
                if self.target_file:
                    src = os.path.join(self.path, self.target_file)
                else:
                    src = full_path
                self._stage_file(src)
            elif filename and event_name in ("IN_DELETE", "IN_MOVED_FROM", "IN_DELETE_SELF"):
                self._unstage_file(filename)

            # Update stats
            self._stats["total"] += 1
            self._stats["by_type"][event_name] = (
                self._stats["by_type"].get(event_name, 0) + 1
            )

    def _stage_file(self, src: str) -> None:
        """Read the source file and write its content directly to changed_files/."""
        dest = os.path.join(self.changed_dir, os.path.basename(src))
        try:
            with open(src, "rb") as f_in:
                data = f_in.read()
            with open(dest, "wb") as f_out:
                f_out.write(data)
            log.info("  -> Written to %s (%d bytes)", dest, len(data))
        except OSError as e:
            log.warning("  -> Could not write %s: %s", dest, e)

    def _unstage_file(self, filename: str) -> None:
        """Remove a file from the changed_files directory if it exists there."""
        dest = os.path.join(self.changed_dir, filename)
        if os.path.exists(dest):
            try:
                os.remove(dest)
                log.info("  -> Removed from staging: %s", dest)
            except OSError as e:
                log.warning("  -> Could not remove %s: %s", dest, e)

    def _print_summary(self) -> None:
        elapsed = time.monotonic() - (self._start_time or 0)
        print("\n" + "─" * 50)
        print(f"  Watcher stopped after {elapsed:.1f}s")
        print(f"  Total events : {self._stats['total']}")
        if self._stats["by_type"]:
            print("  By type:")
            for name, count in sorted(
                self._stats["by_type"].items(), key=lambda x: -x[1]
            ):
                label = EVENT_LABELS.get(name, name)
                print(f"    {label:<25} {count:>5}")
        print("─" * 50)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    watch_path = sys.argv[1] if len(sys.argv) > 1 else "."
    watch_path = os.path.expanduser(watch_path)

    if not os.path.exists(watch_path):
        print(f"Error: path does not exist: {watch_path}")
        sys.exit(1)

    watcher = FileWatcher(
        path=watch_path,
        recursive=True,
        ignore_exts={".swp", ".swx", ".tmp"},
    )
    watcher.watch()


if __name__ == "__main__":
    main()