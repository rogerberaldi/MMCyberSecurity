import whois
import logging
import time
from core.utils import save_text, record_time

logger = logging.getLogger(__name__)

def perform_whois_lookup(domain, output_dir):
    """Realiza a consulta WHOIS para um domínio."""
    start_time = time.time()
    logger.info(f"Iniciando consulta WHOIS para: {domain}")
    try:
        whois_info = whois.whois(domain)
        end_time = time.time()
        record_time(start_time, end_time, f"WHOIS Lookup para {domain}")
        save_text(str(whois_info), f"{output_dir}/whois.txt")
        logger.info(f"Consulta WHOIS para {domain} concluída. Resultados salvos em: {output_dir}/whois.txt")
        return whois_info
    except Exception as e:
        logger.error(f"Erro ao realizar consulta WHOIS para {domain}: {e}")
        return None

if __name__ == '__main__':
    from core.logging_config import setup_logging
    setup_logging(level='DEBUG')
    test_domain = "example.com"
    test_output_dir = "test_output/example.com/footprint"
    import os
    os.makedirs(test_output_dir, exist_ok=True)
    whois_data = perform_whois_lookup(test_domain, test_output_dir)
    if whois_data:
        logger.debug(f"Dados WHOIS de {test_domain}: {whois_data}")
    import shutil
    shutil.rmtree("test_output", ignore_errors=True)
