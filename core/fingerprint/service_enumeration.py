import logging
import json
import os
import time
from core.utils import execute_command, save_json, record_time

logger = logging.getLogger(__name__)

def verify_nmap_availability():
    """Verifica se o nmap está disponível."""
    command = ["which", "nmap"]
    stdout, stderr, returncode = execute_command(command)
    if returncode == 0:
        logger.debug(f"Ferramenta 'nmap' encontrada em: {stdout.strip()}")
        return True
    else:
        logger.warning(f"Ferramenta 'nmap' não encontrada. Certifique-se de que está instalada e no PATH.")
        return False

def perform_service_enumeration(domain, output_dir):
    """Realiza a enumeração de serviços usando o nmap."""
    if not verify_nmap_availability():
        return None

    open_ports_file = f"{output_dir}/open_ports.json"
    if not os.path.exists(open_ports_file):
        logger.warning(f"Arquivo de portas abertas não encontrado: {open_ports_file}. Execute o módulo de port scanning primeiro.")
        return None

    try:
        with open(open_ports_file, 'r') as f:
            open_ports = json.load(f)
    except json.JSONDecodeError:
        logger.error(f"Erro ao decodificar o arquivo JSON de portas abertas: {open_ports_file}")
        return None

    if not open_ports:
        logger.info(f"Nenhuma porta aberta encontrada para {domain}. A enumeração de serviços não será executada.")
        return None

    start_time = time.time()
    output_file = f"{output_dir}/service_scan.xml"
    ports_argument = ",".join(map(str, open_ports))
    
    command = [
        "/usr/bin/sudo", "nmap", 
        "-sV", # -sV para detecção de serviço
        "-p", ports_argument, 
        "-oX", output_file, 
        domain
    ] 
    stdout, stderr, returncode = execute_command(command)
    end_time = time.time()
    
    record_time(start_time, end_time, f"Enumeração de serviços para {domain}")

    if returncode == 0:
        logger.info(f"Enumeração de serviços para {domain} concluída. Resultados salvos em: {output_file}")
        return output_file
    else:
        logger.error(f"Erro ao executar nmap para enumeração de serviços em {domain}: {stderr}")
        return None

if __name__ == '__main__':
    from core.logging_config import setup_logging
    setup_logging(level='DEBUG')
    test_domain = "example.com"
    test_output_dir = "test_output/example.com/fingerprint"
    import os
    os.makedirs(test_output_dir, exist_ok=True)
    # Crie um arquivo open_ports.json de teste
    with open(f"{test_output_dir}/open_ports.json", 'w') as f:
        json.dump([80, 443, 22], f)
    service_scan_output = perform_service_enumeration(test_domain, test_output_dir)
    if service_scan_output:
        logger.debug(f"Saída da enumeração de serviços para {test_domain}: {service_scan_output}")
    import shutil
    shutil.rmtree("test_output", ignore_errors=True)
