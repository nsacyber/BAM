import logging
import logging.handlers
import multiprocessing as mp
import sys
import globs

def log_config():
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    h = logging.FileHandler("log.txt", "a")
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
            print("[BAMERROR] error occurred while handling item from queue: \n" + str(e), file=sys.stderr)
