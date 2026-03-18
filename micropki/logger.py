import logging
from pathlib import Path

def setup_logger(log_file=None):
    logger = logging.getLogger("micropki")
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S"
    )

    # консоль всегда
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(console)

    # файл — если указан
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger