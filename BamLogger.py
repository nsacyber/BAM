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
            # print(str(item)) # , file=open("queueditems.txt", "a")
            if item is None:
                break
            logger = logging.getLogger(item.name)
            logger.handle(item)
        except Exception as e:
            import sys
            print("error occurred while handling item from queue: \n" + str(e), file=sys.stderr)
    print("queue loop broken")
    # globs.QUEUE.close()
    # globs.QUEUE.join_thread()
