import logging
import sys

def setup_logging(level=logging.INFO, log_file='logs/script.log'):
    """Configura o sistema de logging."""
    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f'Nível de log inválido: {level}')

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(module)s - %(message)s')

    # Handler para o arquivo de log
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)

    # Handler para o console (stdout)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)

    logger = logging.getLogger()
    logger.setLevel(numeric_level)
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

    return logger

if __name__ == '__main__':
    logger = setup_logging(level='DEBUG')
    logger.debug('Mensagem de debug')
    logger.info('Mensagem de informação')
    logger.warning('Mensagem de aviso')
    logger.error('Mensagem de erro')
    logger.critical('Mensagem crítica')
