import logging
import sys
from pathlib import Path

def setup_logger(log_file=None):
    log_formatter = logging.Formatter(
        '%(asctime)s.%(msecs)03d - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S'
    )
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(log_file, encoding='utf-8')
    else:
        handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(log_formatter)
    root_logger.addHandler(handler)
    return root_logger