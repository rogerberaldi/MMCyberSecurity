import dns.resolver
import logging
import time

from core.utils import save_json, record_time

logger = logging.getLogger(__name__)

def perform_dns_enumeration(domain, output_dir):
    """Realiza a enumeração de DNS para um domínio."""
    start_time = time.time()
    logger.info(f"Iniciando enumeração de DNS para: {domain}")
    dns_records = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            dns_records[record_type] = [str(rdata) for rdata in answers]
            logger.debug(f"Encontrados registros {record_type} para {domain}: {dns_records[record_type]}")
        except dns.resolver.NoAnswer:
            logger.debug(f"Nenhum registro {record_type} encontrado para {domain}")
        except dns.resolver.NXDOMAIN:
            logger.warning(f"Domínio {domain} não encontrado (NXDOMAIN) ao consultar por {record_type}")
            return None
        except Exception as e:
            logger.error(f"Erro ao consultar registros {record_type} para {domain}: {e}")

    end_time = time.time()
    record_time(start_time, end_time, f"Enumeração de DNS para {domain}")
    save_json(dns_records, f"{output_dir}/dns_enumeration.json")
    logger.info(f"Enumeração de DNS para {domain} concluída. Resultados salvos em: {output_dir}/dns_enumeration.json")
    return dns_records

if __name__ == '__main__':
    from core.logging_config import setup_logging
    setup_logging(level='DEBUG')
    test_domain = "example.com"
    test_output_dir = "test_output/example.com/footprint"
    import os
    os.makedirs(test_output_dir, exist_ok=True)
    dns_data = perform_dns_enumeration(test_domain, test_output_dir)
    if dns_data:
        logger.debug(f"Dados de DNS de {test_domain}: {dns_data}")
    import shutil
    shutil.rmtree("test_output", ignore_errors=True)
