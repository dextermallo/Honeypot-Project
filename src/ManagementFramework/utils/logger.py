import logging


formatter = logging.Formatter('[%(levelname)s] %(asctime)s: %(message)s')
logger = logging.getLogger()
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)