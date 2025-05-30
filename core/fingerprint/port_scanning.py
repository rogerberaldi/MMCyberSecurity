import logging
from core.utils import execute_command, save_text, record_time, save_json
import os
import json
import re
import time

logger = logging.getLogger(__name__)

def verify_tool_availability(tool_name):
    """Verifica se uma ferramenta de linha de comando está disponível."""
    command = ["which", tool_name]
    stdout, stderr, returncode = execute_command(command)
    if returncode == 0:
        logger.debug(f"Ferramenta '{tool_name}' encontrada em: {stdout.strip()}")
        return True
    else:
        logger.warning(f"Ferramenta '{tool_name}' não encontrada. Certifique-se de que está instalada e no PATH.")
        return False

def run_nmap(target_ip, output_dir): # Alterado de 'domain' para 'target_ip'
    """Executa o nmap -sT -p- para realizar a varredura de todas as portas TCP em um IP."""
    if not verify_tool_availability("nmap"):
        return None
    
    start_time = time.time()
    # Nome do arquivo de saída específico para o IP
    # Substitui '.' por '_' no IP para evitar problemas com nomes de arquivo, se houver.
    sanitized_ip_filename = target_ip.replace('.', '_').replace(':', '_') # Adequado para IPv4 e IPv6
    output_file = f"{output_dir}/nmap_tcp_scan_{sanitized_ip_filename}.xml"
    
    logger.info(f"Iniciando Nmap TCP scan (-sT -p-) para o IP: {target_ip}")
    command = ["/usr/bin/sudo", "nmap", "-sT", "-p-", "-oX", output_file, target_ip]
    
    stdout, stderr, returncode = execute_command(command)
    end_time = time.time()
    record_time(start_time, end_time, f"Nmap TCP scan (-sT -p-) para {target_ip}")
    
    if returncode == 0:
        logger.info(f"Nmap TCP scan para {target_ip} concluído. Resultados salvos em: {output_file}")
        return output_file
    else:
        logger.error(f"Erro ao executar nmap TCP scan para {target_ip}: {stderr}")
        if stdout:
            logger.error(f"Nmap stdout: {stdout}")
        return None


# Lista de portas UDP comuns para VoIP/RTP/SIP. Você pode expandir esta lista.
# RTP geralmente usa um range de portas pares.
# SIP: 5060, 5061 (TLS)
# RTP: Comumente na faixa 10000-20000 (pares), mas pode variar.
#       Nmap tem '--defeat-rtp-port-scan' se você quiser evitar que o nmap
#       trate portas RTP de forma especial durante o scan de versão, mas para
#       identificação pode ser útil deixar o comportamento padrão.
# STUN: 3478
# Outros: 5004 (RTP), etc.
DEFAULT_VOIP_UDP_PORTS = "5060,5061,3478,5004,16384-16482" # Exemplo de range RTP

def run_nmap_udp_voip(target_ip, output_dir, udp_ports=DEFAULT_VOIP_UDP_PORTS): # Alterado de 'domain' para 'target_ip'
    """Executa o nmap para realizar a varredura de portas UDP específicas para VoIP."""
    if not verify_tool_availability("nmap"): # Reutilizando sua função de verificação
        return None

    start_time = time.time()
    sanitized_ip_filename = target_ip.replace('.', '_').replace(':', '_')
    output_file = f"{output_dir}/nmap_udp_voip_scan_{sanitized_ip_filename}.xml"

    logger.info(f"Iniciando varredura UDP (-sU -sV) em {domtarget_ipain} nas portas: {udp_ports}")
    
    # -sU: UDP Scan
    # -sV: Service Version Detection
    # --version-intensity 0: (Opcional) Para scans UDP, uma intensidade menor pode ser mais rápida.
    #                          Pode omitir para usar o padrão do Nmap ou ajustar conforme necessário.
    # -T4: (Opcional) Template de timing. Para UDP, T3 ou T2 podem ser mais confiáveis,
    #                mas T4 é mais rápido. Teste o que funciona melhor para sua rede/alvos.
    #                Evite T5 para scans UDP complexos.
    # --max-retries 1 ou 2: (Opcional) Pode acelerar scans UDP ao não tentar tantas vezes em portas que não respondem.
    command = [
        "/usr/bin/sudo", "nmap",
        "-sU",          # Tipo de scan UDP
        "-sV",          # Detecção de versão de serviço
        # "--version-intensity", "0", # Opcional: pode acelerar
        # "-T4",                       # Opcional: ajuste de timing
        # "--max-retries", "1",        # Opcional: pode acelerar
        "-p", udp_ports, # Especifica as portas UDP
        "-oX", output_file,
        domain
    ]
    
    stdout, stderr, returncode = execute_command(command)
    end_time = time.time()
    record_time(start_time, end_time, f"Nmap UDP VoIP para {domain}")

    if returncode == 0:
        logger.info(f"Nmap UDP VoIP scan para {domain} concluído. Resultados salvos em: {output_file}")
        # Você precisará de uma função para parsear este XML e extrair as portas UDP abertas e serviços.
        return output_file
    else:
        logger.error(f"Erro ao executar nmap UDP VoIP para {domain}: {stderr}")
        if stdout:
            logger.error(f"Nmap stdout: {stdout}")
        return None


def run_masscan(ips, output_dir):
    """Executa o masscan para realizar a varredura de portas em uma lista de IPs."""
    if not verify_tool_availability("masscan") or not ips:
        return None
    
    output_file = f"{output_dir}/masscan_scan.txt"
    start_time = time.time()
    
    command = [
        "/usr/bin/sudo",
        "masscan", 
        "-p0-65535", 
        "--rate", "3000"
    ] + ips + ["-oG", output_file]

    stdout, stderr, returncode = execute_command(command)
    end_time = time.time()
    record_time(start_time, end_time, f"Masscan para {ips}")
    if returncode == 0:
        logger.info(f"Masscan scan para {', '.join(ips)} concluído. Resultados salvos em: {output_file}")
        return output_file
    else:
        logger.error(f"Erro ao executar masscan para {', '.join(ips)}: {stderr}")
        return None

def run_rustscan(ips, output_dir, port_range="1-65535"): # Aceita lista de IPs e range de portas
    """Executa o rustscan para realizar a varredura de portas."""
    if not verify_tool_availability("rustscan"):
        return None
    start_time = time.time()
    targets = ",".join(ips) 
    logger.info(f"Executando Rustscan para {targets} nas portas {port_range}.")

    # Adicionado -p para escanear todas as portas por padrão
    command = ["rustscan", "-a", targets, "-p", port_range, "--ulimit", "65535", "--greppable", "--no-nmap"]
    # Adicionado --no-nmap para evitar que o Rustscan chame o Nmap, já que você faz isso depois.
    # Remova '--no-nmap' se você preferir que ele execute e quer parsear uma saída mais complexa (não recomendado no seu fluxo atual).

    stdout, stderr, returncode = execute_command(command)
    end_time = time.time()

    record_time(start_time, end_time, f"Rustscan para {targets}")

    found_ports_by_ip = {}
    if returncode == 0 and stdout:
        # Regex para capturar IP -> [portas]
        # Exemplo de linha: 192.168.1.1 -> [80,443,8080]
        # Ou às vezes sem espaço: 192.168.1.1->[80,443]
        ip_port_pattern = re.compile(r"([\d\.]+|\[[0-9a-fA-F:]+\])\s*->\s*\[(.*?)\]")
        for line in stdout.splitlines():
            match = ip_port_pattern.search(line)
            if match:
                ip = match.group(1)
                ports_str = match.group(2)
                if ports_str: # Verifica se encontrou alguma porta
                    found_ports_by_ip[ip] = [port.strip() for port in ports_str.split(',')]
        logger.info(f"Rustscan scan para {targets} concluído. Portas encontradas: {found_ports_by_ip}")
        return found_ports_by_ip # Retorna um dicionário
    else:
        logger.error(f"Erro ao executar rustscan para {targets}: {stderr if stderr else 'Nenhuma saída ou erro desconhecido.'}")
        if stdout:
            logger.info(f"Saída (stdout) do Rustscan: {stdout}")
        return {} # Retorna dicionário vazio em caso de erro

def perform_port_scanning(domain, output_dir, ips=None):
    """Realiza a varredura de portas usando nmap, masscan e rustscan."""
    logger.info(f"Iniciando varredura de portas para: {domain}")

    # Scans TCP existentes
    nmap_tcp_output = run_nmap(domain, f"{output_dir}")
    masscan_output = run_masscan(ips if ips else [domain], f"{output_dir}")
    rustscan_results_map = run_rustscan(ips if ips else [domain], f"{output_dir}")

    ports = set(rustscan_ports) if rustscan_ports else set()

    if rustscan_results_map:
        # Salva as portas TCP encontradas pelo Rustscan (usado pelo service_enumeration para TCP)
        save_json(rustscan_results_map, f"{output_dir}/open_ports_by_ip.json")
        logger.info(f"Portas abertas (Rustscan) por IP salvas em: {output_dir}/open_ports_by_ip.json")
    else:
         logger.info(f"Nenhuma porta aberta encontrada pelo Rustscan para os IPs fornecidos.")

    logger.info(f"Iniciando varredura UDP específica para VoIP em {domain}")
    nmap_udp_voip_output = run_nmap_udp_voip(domain, output_dir) 
                                            # udp_ports="U:5060,U:5061,U:10000-20000") #

    return {
        "nmap_output": nmap_tcp_output,
        "masscan_output": masscan_output, 
        "rustscan_output": rustscan_results_map, 
        "open_tcp_ports_json": f"{output_dir}/open_ports.json" if ports else None,
        "nmap_udp_voip_output": nmap_udp_voip_output
    }

if __name__ == '__main__':
    from core.logging_config import setup_logging
    setup_logging(level='DEBUG')
    test_domain = "example.com"
    test_output_dir = "test_output/example.com/fingerprint"
    import os
    os.makedirs(test_output_dir, exist_ok=True)
    port_scan_results = perform_port_scanning(test_domain, test_output_dir)
    if port_scan_results:
        logger.debug(f"Resultados da varredura de portas para {test_domain}: {port_scan_results}")
    import shutil
    shutil.rmtree("test_output", ignore_errors=True)
