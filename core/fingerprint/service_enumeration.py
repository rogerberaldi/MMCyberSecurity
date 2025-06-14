import logging
import json
import os
import time
import socket 

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

def run_nmap_service_scan_on_ip(target_ip, tcp_ports_list, output_dir, nmap_cli_args=None):
    """
    Executa o Nmap para enumeração de serviços e scripts em um único IP e suas portas TCP.

    Args:
        target_ip (str): O IP alvo.
        tcp_ports_list (list): Lista de strings ou inteiros representando as portas TCP abertas.
        output_dir (str): Diretório para salvar o arquivo XML de saída.
        nmap_cli_args (list, optional): Lista de argumentos adicionais para o Nmap (ex: ["-sC", "--script=vuln"]).
                                        Por padrão, usará -sV.

    Returns:
        str or None: Caminho para o arquivo XML de saída do Nmap ou None em caso de erro.
    """
    if not tcp_ports_list:
        logger.info(f"Nenhuma porta TCP aberta fornecida para enumeração de serviço no IP {target_ip}.")
        return None

    if not verify_nmap_availability(): # Verificação de disponibilidade do Nmap
         return None

    start_time = time.time()
    sanitized_ip_filename = target_ip.replace('.', '_').replace(':', '_')
    output_file = os.path.join(output_dir, f"service_scan_{sanitized_ip_filename}.xml")

    ports_argument = ",".join(map(str, tcp_ports_list))

    base_command = ["/usr/bin/sudo", "nmap", "-sV"] # -sV é fundamental
    if nmap_cli_args:
        base_command.extend(nmap_cli_args)

    command = base_command + ["-p", ports_argument, "-oX", output_file, target_ip]

    logger.info(f"Executando Nmap Service Scan (comando: {' '.join(command)}) no IP: {target_ip} Portas: {ports_argument}")

    stdout, stderr, returncode = execute_command(command)
    end_time = time.time()
    record_time(start_time, end_time, f"Enumeração de Serviços Nmap para {target_ip} (Portas: {ports_argument})")

    if returncode == 0:
        logger.info(f"Enumeração de serviços Nmap para {target_ip} concluída. Resultados salvos em: {output_file}")
        return output_file
    else:
        logger.error(f"Erro ao executar Nmap para enumeração de serviços em {target_ip}: {stderr}")
        if stdout:
            logger.error(f"Nmap stdout: {stdout}")
        return None

def refactored_perform_service_enumeration(consolidated_open_ports_json_file, base_output_dir, original_target_context="", enable_vuln_scan=False):
    """
    Realiza a enumeração de serviços Nmap para cada IP encontrado no arquivo JSON.

    Args:
        consolidated_open_ports_json_file (str): Caminho para o arquivo JSON contendo {"ip": [portas_tcp_abertas]}.
        base_output_dir (str): Diretório base onde os subdiretórios por IP serão criados para os resultados.
        original_target_context (str): Contexto do alvo original (domínio ou IP inicial) para logging.

    Returns:
        dict: Um dicionário mapeando cada IP para o caminho do seu respectivo arquivo XML de scan de serviço.
              Ex: {"ip1": "path/to/service_scan_ip1.xml", ...}
    """
    if not consolidated_open_ports_json_file or not os.path.exists(consolidated_open_ports_json_file):
        logger.warning(f"Arquivo CONSOLIDADO de portas abertas por IP não encontrado: {consolidated_open_ports_json_file}. "
                       f"Contexto: {original_target_context}. Pulando enumeração de serviço.")
        return {}

    try:
        with open(consolidated_open_ports_json_file, 'r') as f: # << LÊ O NOVO ARQUIVO
            open_ports_data_map = json.load(f)
    except json.JSONDecodeError:
        logger.error(f"Erro ao decodificar o arquivo JSON de portas abertas por IP: {consolidated_open_ports_json_file}. "
                     f"Contexto: {original_target_context}.")
        return {}

    if not open_ports_data_map:
        logger.info(f"Nenhum dado de portas abertas por IP encontrado em {consolidated_open_ports_json_file} "
                    f"para {original_target_context}. A enumeração de serviços não será executada.")
        return {}

    service_scan_xml_map = {}
    logger.info(f"Iniciando enumeração de serviços Nmap para múltiplos IPs. Contexto: {original_target_context}")
    nmap_args_for_ip = []  # Argumentos Nmap específicos para cada IP
    for ip_address, tcp_ports in open_ports_data_map.items():
        if not tcp_ports:
            logger.info(f"Nenhuma porta TCP listada para o IP {ip_address} em {original_target_context}. Pulando Nmap scan para este IP.")
            continue

        # Cria um subdiretório para os resultados deste IP específico dentro do base_output_dir do fingerprint
        ip_specific_output_dir = os.path.join(base_output_dir, ip_address.replace('.', '_').replace(':', '_'))
        os.makedirs(ip_specific_output_dir, exist_ok=True)

        # --- Escolha dos Argumentos Nmap para "Extrair o Melhor" ---
        # -sC: executa scripts NSE padrão. Bom para descoberta e algumas verificações de segurança leves.
        # --version-intensity 9: Tenta mais probes para detecção de versão (mais lento).
        # --script=vuln: Focado em scripts de vulnerabilidade (PODE SER MUITO LENTO e INTRUSIVO).
        
        # Para um bom equilíbrio inicial, -sC é uma ótima adição ao -sV.
        # Você pode tornar isso configurável no futuro.
        nmap_args_for_ip = ["-sC"] # Adiciona scripts padrão
        if enable_vuln_scan:
            logger.warning(f"MODO INTRUSIVO HABILITADO para {ip_address}: Adicionando Nmap --script=vuln.")
            nmap_args_for_ip.append("--script=default,vuln") 
            nmap_args_for_ip.extend(["--version-intensity", "9"]) # Opcional: mais detalhado, mais lento
        # nmap_args_for_ip.extend(["--script=default,discovery,version,vuln"]) # Exemplo mais agressivo

        logger.info(f"Iniciando Nmap scan de serviço/script para IP: {ip_address} (Portas: {tcp_ports}) "
                    f"Contexto: {original_target_context}")

        xml_path = run_nmap_service_scan_on_ip(ip_address, tcp_ports, ip_specific_output_dir, 
                                               nmap_cli_args=nmap_args_for_ip)
        if xml_path:
            service_scan_xml_map[ip_address] = xml_path

    logger.info(f"Enumeração de serviços Nmap para múltiplos IPs concluída. Contexto: {original_target_context}")
    return service_scan_xml_map



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
    service_scan_output = refactored_perform_service_enumeration(test_domain, test_output_dir)
    if service_scan_output:
        logger.debug(f"Saída da enumeração de serviços para {test_domain}: {service_scan_output}")
    import shutil
    shutil.rmtree("test_output", ignore_errors=True)
