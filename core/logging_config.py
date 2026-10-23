"""Central logging for OSINT EYE library code (core/, graph/, reporting/).

User-facing console output stays in ui/ (Rich panels, wizard, dashboard);
everything else that used to print() goes through the ``osint_eye`` logger
hierarchy so it can be filtered with ``--log-level`` and persisted with
``--log-file``. One call to :func:`setup_logging` configures the whole
tree because every library module logs via ``logging.getLogger(__name__)``
and ``osint_eye`` is their common ancestor.
"""

import logging
import sys
from pathlib import Path

ROOT_LOGGER = "osint_eye"

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

LEVEL_NAMES = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


def parse_level(value) -> int:
    """Parse a level name ('info', 'DEBUG'...) into a logging level.

    Raises ``ValueError`` for unknown names so argparse can turn it into
    a clean usage error instead of a raw traceback.
    """
    name = str(value).strip().upper()
    if name not in LEVEL_NAMES:
        raise ValueError(f"log level debe ser uno de: {', '.join(LEVEL_NAMES)}")
    return getattr(logging, name)


def get_logger(name: str = None) -> logging.Logger:
    """Logger inside the osint_eye tree.

    ``get_logger("core.monitor")`` → ``osint_eye.core.monitor``, so one
    :func:`setup_logging` call on the ``osint_eye`` root configures every
    library module. Without ``name``, returns the root itself.
    """
    if name is None:
        return logging.getLogger(ROOT_LOGGER)
    if name.startswith(ROOT_LOGGER + "."):
        return logging.getLogger(name)
    return logging.getLogger(f"{ROOT_LOGGER}.{name}")


def setup_logging(level="INFO", log_file=None) -> logging.Logger:
    """(Re)configure the ``osint_eye`` logger tree. Idempotent.

    * console handler on stderr at ``level`` (keeps stdout clean for data);
    * optional append-mode file handler (parent dirs are created);
    * previous handlers are replaced, so calling it twice (wizard → main,
      test re-runs) never duplicates output.

    Returns the ``osint_eye`` root logger.
    """
    resolved = level if isinstance(level, int) else parse_level(level)
    root = logging.getLogger(ROOT_LOGGER)
    root.setLevel(resolved)

    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()

    formatter = logging.Formatter(LOG_FORMAT)

    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(formatter)
    root.addHandler(console)

    if log_file:
        path = Path(str(log_file))
        if str(path.parent) not in ("", "."):
            path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(str(path), encoding="utf-8")
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

    return root
