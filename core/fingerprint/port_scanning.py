import logging
from core.utils import execute_command, save_text, record_time, save_json
import os
import json
import re
import time
import xml.etree.ElementTree as ET

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

    logger.info(f"Iniciando varredura UDP (-sU -sV) em {target_ip} nas portas: {udp_ports}")
    
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
        target_ip
    ]
    
    stdout, stderr, returncode = execute_command(command)
    end_time = time.time()
    record_time(start_time, end_time, f"Nmap UDP VoIP para {target_ip}")

    if returncode == 0:
        logger.info(f"Nmap UDP VoIP scan para {target_ip} concluído. Resultados salvos em: {output_file}")
        # Você precisará de uma função para parsear este XML e extrair as portas UDP abertas e serviços.
        return output_file
    else:
        logger.error(f"Erro ao executar nmap UDP VoIP para {target_ip}: {stderr}")
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
    command = ["rustscan", "-a", targets, "-r", port_range, "--ulimit", "65535", "--greppable"]
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
                    found_ports_by_ip[ip] = [port.strip() for port in ports_str.split(',') if port.strip()]
                else:
                    found_ports_by_ip[ip] = [] # IP encontrado, mas nenhuma porta aberta listada

        if found_ports_by_ip:
            logger.info(f"Rustscan scan para {targets} concluído. Portas encontradas: {found_ports_by_ip}")
        else:
            logger.info(f"Rustscan scan para {targets} concluído, mas nenhuma porta parseada da saída. Saída (stdout): {stdout}")

        return found_ports_by_ip # Retorna um dicionário
    else:
        logger.error(f"Erro ao executar rustscan para {targets}: {stderr if stderr else 'Nenhuma saída ou erro desconhecido.'}")
        if stdout:
            logger.info(f"Saída (stdout) do Rustscan: {stdout}")
        return {} # Retorna dicionário vazio em caso de erro


def parse_masscan_output(file_path):
    ports_by_ip = {}
    if not file_path or not os.path.exists(file_path):
        logger.warning(f"Arquivo de saída do Masscan não encontrado ou caminho nulo: {file_path}")
        return ports_by_ip
    try:
        with open(file_path, 'r') as f:
            for line in f:
                if line.startswith("#"):
                    continue
                parts = line.split()
                try:
                    # Estrutura esperada: Timestamp: ... Host: <IP> ... Ports: <PORT>/open/tcp...
                    host_keyword_idx = parts.index("Host:")
                    ip = parts[host_keyword_idx + 1]

                    ports_keyword_idx = parts.index("Ports:")
                    port_full_info = parts[ports_keyword_idx + 1]
                    port_str = port_full_info.split('/')[0]

                    if ip not in ports_by_ip:
                        ports_by_ip[ip] = set()
                    ports_by_ip[ip].add(int(port_str))
                except (ValueError, IndexError, TypeError):
                    # ValueError se "Host:" ou "Ports:" não encontrado, ou port_str não for int
                    # IndexError se parts[idx+1] não existir
                    logger.warning(f"Não foi possível parsear a linha do Masscan: {line.strip()}")
                    continue

        # Converter sets para listas ordenadas
        for ip_addr in ports_by_ip:
            ports_by_ip[ip_addr] = sorted(list(ports_by_ip[ip_addr]))
        logger.info(f"Portas parseadas do Masscan ({file_path}): {len(ports_by_ip)} IPs com portas.")
        return ports_by_ip
    except Exception as e:
        logger.error(f"Erro ao ler ou parsear arquivo do Masscan {file_path}: {e}")
        return {}

def parse_nmap_xml_for_open_tcp_ports(xml_file_path):
    open_ports = set()
    if not xml_file_path or not os.path.exists(xml_file_path):
        logger.warning(f"Arquivo XML do Nmap não encontrado ou caminho nulo: {xml_file_path}")
        return [] # Retorna lista de portas para um único arquivo XML (um IP)
    try:
        tree = ET.parse(xml_file_path)
        root = tree.getroot()
        # Procura por portas TCP com estado 'open' dentro de qualquer host no XML
        # Normalmente, nossos XMLs de -sT -p- por IP terão apenas um host.
        for port_element in root.findall(".//host/ports/port[@protocol='tcp']"):
            state_element = port_element.find("state[@state='open']")
            if state_element is not None:
                portid = port_element.get('portid')
                if portid:
                    open_ports.add(int(portid))

        sorted_ports = sorted(list(open_ports))
        logger.info(f"Portas TCP abertas parseadas do Nmap XML {xml_file_path}: {sorted_ports}")
        return sorted_ports
    except ET.ParseError as e:
        logger.error(f"Erro de parsing no arquivo XML do Nmap {xml_file_path}: {e}")
        return []
    except Exception as e:
        logger.error(f"Erro inesperado ao ler ou parsear arquivo XML do Nmap {xml_file_path}: {e}")
        return []
    

def perform_port_scanning(domain_context, output_dir, ips_list=None, voip=False):
    logger.info(f"Iniciando varredura DE PORTAS CONSOLIDADA para '{domain_context}' nos IPs: {ips_list}")

    results = {
        "nmap_tcp_scan_outputs_by_ip": {},      # IP -> Caminho XML do Nmap TCP (-sT -p-)
        "nmap_udp_voip_scan_outputs_by_ip": {},# IP -> Caminho XML do Nmap UDP VoIP
        "masscan_output_file": None,
        "masscan_ports_by_ip": {},             # IP -> [portas] do Masscan
        "rustscan_ports_by_ip": {},            # IP -> [portas] do Rustscan
        "nmap_sT_ports_by_ip": {},             # IP -> [portas] do Nmap -sT
        "consolidated_open_ports_by_ip_json_file": None # Arquivo JSON com todas as portas TCP abertas consolidadas
    }

    if not ips_list:
        logger.warning(f"Nenhuma lista de IPs fornecida para varredura (contexto: {domain_context}).")
        return results

    # 1. Executar Nmap TCP (-sT -p-) para cada IP
    for ip in ips_list:
        tcp_scan_xml = run_nmap(ip, output_dir) # run_nmap já salva por IP
        if tcp_scan_xml:
            results["nmap_tcp_scan_outputs_by_ip"][ip] = tcp_scan_xml
            # Parsear imediatamente para obter as portas
            nmap_sT_ports = parse_nmap_xml_for_open_tcp_ports(tcp_scan_xml)
            if nmap_sT_ports:
                results["nmap_sT_ports_by_ip"][ip] = nmap_sT_ports

        if voip:
            # Se voip for True, executar o Nmap UDP VoIP scan
            logger.info(f"Iniciando varredura Nmap UDP VoIP para o IP: {ip}")
            # Nmap UDP VoIP Scan (já implementado para ser por IP)
            udp_voip_scan_xml = run_nmap_udp_voip(ip, output_dir)
            if udp_voip_scan_xml:
                results["nmap_udp_voip_scan_outputs_by_ip"][ip] = udp_voip_scan_xml

    # 2. Executar Masscan
    masscan_file = run_masscan(ips_list, output_dir) # Ajuste a taxa
    results["masscan_output_file"] = masscan_file
    if masscan_file:
        results["masscan_ports_by_ip"] = parse_masscan_output(masscan_file)

    # 3. Executar Rustscan

    rustscan_map = run_rustscan(ips_list, output_dir, port_range="1-65535")
    if rustscan_map:
        results["rustscan_ports_by_ip"] = rustscan_map
        rustscan_json_path = os.path.join(output_dir, "rustscan_open_ports_by_ip.json")
        # O JSON apenas do Rustscan pode ser útil para depuração, mas o principal será o consolidado.
        try:
            save_json(rustscan_map, rustscan_json_path)
            logger.info(f"Resultados brutos do Rustscan salvos em: {rustscan_json_path}")
            results["rustscan_output_json_file"] = rustscan_json_path
        except Exception as e:
            logger.error(f"Falha ao salvar o arquivo JSON dos resultados do Rustscan: {e}")

    # 4. Consolidar todas as portas TCP encontradas
    logger.info("Iniciando consolidação de portas TCP abertas de todas as fontes...")
    consolidated_ports_map = {}

    rustscan_data = results.get("rustscan_ports_by_ip", {}) or {}
    masscan_data = results.get("masscan_ports_by_ip", {}) or {}
    nmap_sT_data = results.get("nmap_sT_ports_by_ip", {}) or {}
    
    all_ips_seen = set(rustscan_data.keys()) | \
                       set(masscan_data.keys()) | \
                       set(nmap_sT_data.keys())

    for ip in all_ips_seen:
        unique_int_ports = set()  # Este set armazenará apenas inteiros
        # Processar portas do Rustscan (strings, precisam de conversão para int)
        for port_str in rustscan_data.get(ip, []):
            try:
                unique_int_ports.add(int(port_str))
            except ValueError:
                logger.warning(f"Não foi possível converter a porta '{port_str}' do Rustscan para inteiro para o IP {ip}.")
        # Processar portas do Masscan (devem ser inteiros do parser)
        for port_val in masscan_data.get(ip, []): # Esperado ser lista de ints
            try:
                unique_int_ports.add(int(port_val)) # int() é seguro mesmo se já for int
            except ValueError: # Caso o parser do Masscan retorne algo inesperado
                logger.warning(f"Não foi possível converter a porta '{port_val}' do Masscan para inteiro para o IP {ip}.")
        # Processar portas do Nmap -sT (devem ser inteiros do parser)
        for port_val in nmap_sT_data.get(ip, []): # Esperado ser lista de ints
            try:
                unique_int_ports.add(int(port_val)) # int() é seguro mesmo se já for int
            except ValueError: # Caso o parser do Nmap retorne algo inesperado
                logger.warning(f"Não foi possível converter a porta '{port_val}' do Nmap -sT para inteiro para o IP {ip}.")
        
        if unique_int_ports:
             # Agora unique_int_ports contém apenas inteiros únicos
             consolidated_ports_map[ip] = sorted(list(unique_int_ports)) 


    consolidated_json_path = os.path.join(output_dir, "consolidated_open_tcp_ports_by_ip.json")
    save_json(consolidated_ports_map, consolidated_json_path)

    if consolidated_ports_map:
        results["consolidated_open_ports_by_ip_json_file"] = consolidated_json_path
        logger.info(f"Portas TCP abertas CONSOLIDADAS por IP salvas em: {consolidated_json_path}")
        # Log para verificar o conteúdo
        logger.debug(f"Conteúdo do JSON consolidado para {domain_context}: {consolidated_ports_map}")
    else:
        logger.info(f"Nenhuma porta TCP aberta encontrada por nenhuma ferramenta para os IPs em {domain_context}. {consolidated_json_path} criado, mas vazio.")
        
    logger.info(f"Varredura de portas consolidada para '{domain_context}' concluída.")
    return results




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
