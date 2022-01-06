import logging
import logging.handlers
import multiprocessing as mp
import globs

def log_config():
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    h = logging.handlers.RotatingFileHandler("log.txt", "w")
    logger.addHandler(h)

def log_listener(queue, config):
    config()
    while True:
        try:
            item = queue.get()
            if item is None:
                break
            logger = logging.getLogger(item.name)
            logger.handle(item)
        except Exception as e:
            import sys
            print("[LOGERROR] error occurred while handling item from queue: \n" + str(e), file=sys.stderr)
