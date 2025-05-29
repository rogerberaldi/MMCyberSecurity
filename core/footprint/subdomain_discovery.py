import logging
import time
from core.utils import execute_command, save_text, record_time
import os

logger = logging.getLogger(__name__)

def run_subfinder(domain, output_dir):
    """Executa o subfinder para descobrir subdomínios."""
    start_time = time.time()
    logger.info(f"Executando subfinder para: {domain}")
    output_file = f"{output_dir}/subdomains_subfinder.txt"
    command = ["subfinder", "-d", domain, "-o", output_file]
    stdout, stderr, returncode = execute_command(command)
    end_time = time.time()
    record_time(start_time, end_time, f"Subfinder para {domain}")
    if returncode == 0:
        logger.info(f"Subfinder encontrou subdomínios para {domain}. Resultados salvos em: {output_file}")
        with open(output_file, 'r') as f:
            return [line.strip() for line in f.readlines()]
    else:
        logger.warning(f"Subfinder não encontrou subdomínios ou ocorreu um erro para {domain}: {stderr}")
        return []

def run_amass(domain, output_dir):
    """Executa o amass para descobrir subdomínios."""
    start_time = time.time()
    logger.info(f"Executando amass para: {domain}")
    output_file = f"{output_dir}/subdomains_amass.txt"
    command = ["amass", "enum", "-d", domain, "-o", output_file]
    stdout, stderr, returncode = execute_command(command)
    end_time = time.time()
    record_time(start_time, end_time, f"Amass para {domain}")
    if returncode == 0:
        logger.info(f"Amass encontrou subdomínios para {domain}. Resultados salvos em: {output_file}")
        with open(output_file, 'r') as f:
            return [line.strip() for line in f.readlines()]
    else:
        logger.warning(f"Amass não encontrou subdomínios ou ocorreu um erro para {domain}: {stderr}")
        return []

def perform_subdomain_discovery(domain, output_dir):
    """Realiza a descoberta de subdomínios usando subfinder e amass."""
    logger.info(f"Iniciando descoberta de subdomínios para: {domain}")
    subfinder_results = run_subfinder(domain, output_dir)
    amass_results = run_amass(domain, output_dir)
    all_subdomains = sorted(list(set(subfinder_results + amass_results)))
    save_text("\n".join(all_subdomains), f"{output_dir}/all_subdomains.txt")
    logger.info(f"Descoberta de subdomínios para {domain} concluída. Total de subdomínios encontrados: {len(all_subdomains)}")
    return all_subdomains

if __name__ == '__main__':
    from core.logging_config import setup_logging
    setup_logging(level='DEBUG')
    test_domain = "example.com"
    test_output_dir = "test_output/example.com/footprint"
    import os
    os.makedirs(test_output_dir, exist_ok=True)
    subdomains = perform_subdomain_discovery(test_domain, test_output_dir)
    if subdomains:
        logger.debug(f"Subdomínios encontrados para {test_domain}: {subdomains}")
    import shutil
    shutil.rmtree("test_output", ignore_errors=True)
