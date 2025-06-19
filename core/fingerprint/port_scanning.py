import logging
from core.utils import execute_command, save_text, record_time, save_json, verify_tool_availability
import os
import json
import re
import time
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

def run_nmap(target_ip, output_dir, scan_type="tcp_full"):
    """
    Executa diferentes tipos de varredura Nmap.
    
    Args:
        target_ip: IP alvo
        output_dir: Diretório de saída
        scan_type: Tipo de scan ("tcp_full", "tcp_top1000", "udp_voip")
    """
    if not verify_tool_availability("nmap"):
        return None
    
    start_time = time.time()
    sanitized_ip_filename = target_ip.replace('.', '_').replace(':', '_')
    
    # Define scan parameters based on type
    scan_configs = {
        "tcp_full": {
            "args": ["-sT", "-p-"],
            "output_file": f"{output_dir}/nmap_tcp_scan_{sanitized_ip_filename}.xml"
        },
        "tcp_top1000": {
            "args": ["-sT", "--top-ports", "1000"],
            "output_file": f"{output_dir}/nmap_tcp_top1000_{sanitized_ip_filename}.xml"
        },
        "udp_voip": {
            "args": ["-sU", "-sV", "-p", "5060,5061,3478,5004,16384-16482"],
            "output_file": f"{output_dir}/nmap_udp_voip_scan_{sanitized_ip_filename}.xml"
        }
    }
    
    if scan_type not in scan_configs:
        logger.error(f"Tipo de scan inválido: {scan_type}")
        return None
    
    config = scan_configs[scan_type]
    output_file = config["output_file"]
    
    logger.info(f"Iniciando Nmap {scan_type} scan para o IP: {target_ip}")
    
    # Build command with timeout and optimization flags
    command = ["/usr/bin/sudo", "nmap"] + config["args"] + [
        "-oX", output_file,
        "--max-retries", "2",
        "--host-timeout", "30m",
        "--max-scan-delay", "10ms",
        target_ip
    ]
    
    stdout, stderr, returncode = execute_command(command)
    end_time = time.time()
    record_time(start_time, end_time, f"Nmap {scan_type} scan para {target_ip}")
    
    # Enhanced error checking
    if returncode == 0 and os.path.exists(output_file):
        # Verify XML is valid
        try:
            ET.parse(output_file)
            logger.info(f"Nmap {scan_type} scan para {target_ip} concluído. Resultados salvos em: {output_file}")
            return output_file
        except ET.ParseError as e:
            logger.error(f"XML inválido gerado pelo Nmap: {e}")
            return None
    else:
        # Check if file exists but command failed
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            try:
                ET.parse(output_file)
                logger.info(f"Nmap {scan_type} scan para {target_ip} concluído com avisos (código {returncode}). Resultados em: {output_file}")
                return output_file
            except ET.ParseError:
                logger.error(f"XML corrompido gerado pelo Nmap para {target_ip}")
                return None

        logger.error(f"Erro ao executar nmap {scan_type} para {target_ip}. Código: {returncode}, stderr: {stderr}")
        if stdout:
            logger.debug(f"Nmap stdout: {stdout}")
        return None

def run_masscan(ips, output_dir, rate=1000):
    """Executa o masscan com melhor tratamento de erros."""
    if not verify_tool_availability("masscan") or not ips:
        return None
    
    output_file = f"{output_dir}/masscan_scan.txt"
    start_time = time.time()
    
    # Validate IPs before scanning
    valid_ips = []
    for ip in ips:
        if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ip):
            valid_ips.append(ip)
        else:
            logger.warning(f"IP inválido ignorado pelo Masscan: {ip}")
    
    if not valid_ips:
        logger.error("Nenhum IP válido para o Masscan")
        return None
    
    command = [
        "/usr/bin/sudo",
        "masscan", 
        "-p1-65535", 
        "--rate", str(rate),
        "--wait", "3",
        "--retries", "2"
    ] + valid_ips + ["-oG", output_file]

    logger.info(f"Executando Masscan para {len(valid_ips)} IPs com taxa {rate}")
    stdout, stderr, returncode = execute_command(command)
    end_time = time.time()
    record_time(start_time, end_time, f"Masscan para {valid_ips}")
    
    if returncode == 0 and os.path.exists(output_file):
        logger.info(f"Masscan scan concluído. Resultados salvos em: {output_file}")
        return output_file
    else:
        logger.error(f"Erro ao executar masscan: {stderr}")
        return None

def run_rustscan(ips, output_dir, port_range="1-65535", timeout=3000):
    """Executa o rustscan com configurações otimizadas."""
    if not verify_tool_availability("rustscan"):
        return None
        
    start_time = time.time()
    targets = ",".join(ips)
    
    logger.info(f"Executando Rustscan para {targets} nas portas {port_range}")

    command = [
        "rustscan", 
        "-a", targets, 
        "-r", port_range, 
        "--ulimit", "65535", 
        "--timeout", str(timeout),
        "--tries", "2",
        "--greppable"
    ]

    stdout, stderr, returncode = execute_command(command)
    end_time = time.time()
    record_time(start_time, end_time, f"Rustscan para {targets}")

    found_ports_by_ip = {}
    
    if stdout:
        # Enhanced parsing with better error handling
        ip_port_pattern = re.compile(r"([\d\.]+|\[[0-9a-fA-F:]+\])\s*->\s*\[(.*?)\]")
        for line in stdout.splitlines():
            match = ip_port_pattern.search(line)
            if match:
                ip = match.group(1)
                ports_str = match.group(2)
                
                if ports_str.strip():
                    try:
                        # Validate port numbers
                        ports = []
                        for port in ports_str.split(','):
                            port = port.strip()
                            if port.isdigit() and 1 <= int(port) <= 65535:
                                ports.append(port)
                        found_ports_by_ip[ip] = ports
                    except ValueError as e:
                        logger.warning(f"Erro ao parsear portas para IP {ip}: {e}")
                else:
                    found_ports_by_ip[ip] = []

        if found_ports_by_ip:
            logger.info(f"Rustscan encontrou portas: {found_ports_by_ip}")
        else:
            logger.info(f"Rustscan não encontrou portas abertas ou falha no parsing. Saída: {stdout[:200]}...")

    if returncode != 0 and stderr:
        logger.warning(f"Rustscan terminou com código {returncode}: {stderr}")

    return found_ports_by_ip

def parse_masscan_output(file_path):
    """Parse Masscan output with enhanced error handling."""
    ports_by_ip = {}
    if not file_path or not os.path.exists(file_path):
        logger.warning(f"Arquivo de saída do Masscan não encontrado: {file_path}")
        return ports_by_ip
        
    try:
        with open(file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                    
                try:
                    # Enhanced parsing for different Masscan output formats
                    if "Host:" in line and "Ports:" in line:
                        parts = line.split()
                        host_idx = parts.index("Host:")
                        ports_idx = parts.index("Ports:")
                        
                        if host_idx + 1 < len(parts) and ports_idx + 1 < len(parts):
                            ip = parts[host_idx + 1]
                            port_info = parts[ports_idx + 1]
                            
                            # Validate IP format
                            if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ip):
                                port_str = port_info.split('/')[0]
                                if port_str.isdigit():
                                    port = int(port_str)
                                    if 1 <= port <= 65535:
                                        if ip not in ports_by_ip:
                                            ports_by_ip[ip] = set()
                                        ports_by_ip[ip].add(port)
                                    
                except (ValueError, IndexError) as e:
                    logger.debug(f"Linha {line_num} do Masscan não pôde ser parseada: {line.strip()} - {e}")
                    continue

        # Convert sets to sorted lists
        for ip_addr in ports_by_ip:
            ports_by_ip[ip_addr] = sorted(list(ports_by_ip[ip_addr]))
            
        logger.info(f"Masscan parsing concluído: {len(ports_by_ip)} IPs com portas abertas")
        return ports_by_ip
        
    except Exception as e:
        logger.error(f"Erro ao ler arquivo do Masscan {file_path}: {e}")
        return {}

def parse_nmap_xml_for_open_tcp_ports(xml_file_path):
    """Parse Nmap XML with enhanced error handling."""
    open_ports = set()
    if not xml_file_path or not os.path.exists(xml_file_path):
        logger.warning(f"Arquivo XML do Nmap não encontrado: {xml_file_path}")
        return []
        
    try:
        tree = ET.parse(xml_file_path)
        root = tree.getroot()
        
        # Find all open TCP ports
        for port_element in root.findall(".//host/ports/port[@protocol='tcp']"):
            state_element = port_element.find("state[@state='open']")
            if state_element is not None:
                portid = port_element.get('portid')
                if portid and portid.isdigit():
                    port_num = int(portid)
                    if 1 <= port_num <= 65535:
                        open_ports.add(port_num)

        sorted_ports = sorted(list(open_ports))
        logger.info(f"Nmap XML parsing: {len(sorted_ports)} portas TCP abertas encontradas")
        return sorted_ports
        
    except ET.ParseError as e:
        logger.error(f"Erro de parsing no arquivo XML do Nmap {xml_file_path}: {e}")
        return []
    except Exception as e:
        logger.error(f"Erro inesperado ao processar XML do Nmap {xml_file_path}: {e}")
        return []

def perform_port_scanning(domain_context, output_dir, ips_list=None, voip=False, fast_mode=False):
    """
    Realiza varredura de portas consolidada com modo rápido opcional.
    
    Args:
        domain_context: Contexto do domínio/alvo
        output_dir: Diretório de saída
        ips_list: Lista de IPs para escanear
        voip: Se deve incluir scan UDP VoIP
        fast_mode: Se deve usar scan rápido (top 1000 portas)
    """
    logger.info(f"Iniciando varredura de portas para '{domain_context}' nos IPs: {ips_list}")

    results = {
        "nmap_tcp_scan_outputs_by_ip": {},
        "nmap_udp_voip_scan_outputs_by_ip": {},
        "masscan_output_file": None,
        "masscan_ports_by_ip": {},
        "rustscan_ports_by_ip": {},
        "nmap_sT_ports_by_ip": {},
        "consolidated_open_ports_by_ip_json_file": None
    }

    if not ips_list:
        logger.warning(f"Nenhuma lista de IPs fornecida para varredura (contexto: {domain_context}).")
        return results

    # 1. Execute Nmap TCP scans for each IP
    scan_type = "tcp_top1000" if fast_mode else "tcp_full"
    for ip in ips_list:
        tcp_scan_xml = run_nmap(ip, output_dir, scan_type)
        if tcp_scan_xml:
            results["nmap_tcp_scan_outputs_by_ip"][ip] = tcp_scan_xml
            nmap_sT_ports = parse_nmap_xml_for_open_tcp_ports(tcp_scan_xml)
            if nmap_sT_ports:
                results["nmap_sT_ports_by_ip"][ip] = nmap_sT_ports

        # VoIP UDP scan if requested
        if voip:
            logger.info(f"Iniciando varredura Nmap UDP VoIP para o IP: {ip}")
            udp_voip_scan_xml = run_nmap(ip, output_dir, "udp_voip")
            if udp_voip_scan_xml:
                results["nmap_udp_voip_scan_outputs_by_ip"][ip] = udp_voip_scan_xml

    # 2. Execute Masscan (skip in fast mode for single IPs)
    if not fast_mode or len(ips_list) > 1:
        masscan_file = run_masscan(ips_list, output_dir, rate=2000)
        results["masscan_output_file"] = masscan_file
        if masscan_file:
            results["masscan_ports_by_ip"] = parse_masscan_output(masscan_file)

    # 3. Execute Rustscan
    port_range = "1-1000" if fast_mode else "1-65535"
    rustscan_map = run_rustscan(ips_list, output_dir, port_range=port_range)
    if rustscan_map:
        results["rustscan_ports_by_ip"] = rustscan_map

    # 4. Consolidate all TCP ports found
    logger.info("Consolidando portas TCP abertas de todas as fontes...")
    consolidated_ports_map = {}

    rustscan_data = results.get("rustscan_ports_by_ip", {}) or {}
    masscan_data = results.get("masscan_ports_by_ip", {}) or {}
    nmap_sT_data = results.get("nmap_sT_ports_by_ip", {}) or {}
    
    all_ips_seen = set(rustscan_data.keys()) | set(masscan_data.keys()) | set(nmap_sT_data.keys())

    for ip in all_ips_seen:
        unique_int_ports = set()
        
        # Process Rustscan ports
        for port_str in rustscan_data.get(ip, []):
            try:
                unique_int_ports.add(int(port_str))
            except ValueError:
                logger.warning(f"Porta inválida do Rustscan: '{port_str}' para IP {ip}")
        
        # Process Masscan ports
        for port_val in masscan_data.get(ip, []):
            try:
                unique_int_ports.add(int(port_val))
            except ValueError:
                logger.warning(f"Porta inválida do Masscan: '{port_val}' para IP {ip}")
        
        # Process Nmap ports
        for port_val in nmap_sT_data.get(ip, []):
            try:
                unique_int_ports.add(int(port_val))
            except ValueError:
                logger.warning(f"Porta inválida do Nmap: '{port_val}' para IP {ip}")
        
        if unique_int_ports:
            consolidated_ports_map[ip] = sorted(list(unique_int_ports))

    # Save consolidated results
    consolidated_json_path = os.path.join(output_dir, "consolidated_open_tcp_ports_by_ip.json")
    save_json(consolidated_ports_map, consolidated_json_path)

    if consolidated_ports_map:
        results["consolidated_open_ports_by_ip_json_file"] = consolidated_json_path
        logger.info(f"Portas TCP consolidadas salvas em: {consolidated_json_path}")
        
        # Log summary
        total_ports = sum(len(ports) for ports in consolidated_ports_map.values())
        logger.info(f"Resumo: {len(consolidated_ports_map)} IPs, {total_ports} portas TCP abertas total")
    else:
        logger.info(f"Nenhuma porta TCP aberta encontrada para {domain_context}")
        
    logger.info(f"Varredura de portas para '{domain_context}' concluída.")
    return results

if __name__ == '__main__':
    from core.logging_config import setup_logging
    setup_logging(level='DEBUG')
    test_domain = "example.com"
    test_output_dir = "test_output/example.com/fingerprint"
    import os
    os.makedirs(test_output_dir, exist_ok=True)
    
    # Test with a public IP
    test_ips = ["8.8.8.8"]
    port_scan_results = perform_port_scanning(test_domain, test_output_dir, ips_list=test_ips, fast_mode=True)
    if port_scan_results:
        logger.debug(f"Resultados da varredura de portas para {test_domain}: {port_scan_results}")
    
    import shutil
    shutil.rmtree("test_output", ignore_errors=True)