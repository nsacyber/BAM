import logging
import logging.handlers
from pyclbr import Function
from queue import Queue

def log_config():
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    h = logging.handlers.RotatingFileHandler("log.txt", "w")
    logger.addHandler(h)

def log_listener(queue: Queue, config: Function):
    config()
    while True:
        try:
            item = queue.get(timeout=60)
            if item is None:
                break
            logger = logging.getLogger(item.name)
            logger.handle(item)
        except KeyboardInterrupt:
            logger.log(logging.INFO, "[LOGLISTENER] execution stopped by user")
            break
        except Exception as e:
            logger.log(logging.ERROR, "[LOGERROR] error occurred while handling item from queue: \n" + str(e))
        