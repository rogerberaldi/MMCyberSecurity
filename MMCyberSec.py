import argparse
import logging
import os
import concurrent.futures
import time
import socket
import sys

from core.logging_config import setup_logging

from core.footprint.whois_lookup import perform_whois_lookup
from core.footprint.dns_enumeration import perform_dns_enumeration
from core.footprint.subdomain_discovery import perform_subdomain_discovery
from core.footprint.ip_asn_mapping import perform_ip_asn_mapping
from core.footprint.dns_history import perform_dns_history
from core.footprint.geolocation import perform_geolocation
from core.footprint.related_domains import perform_related_domains

from core.fingerprint.port_scanning import perform_port_scanning
from core.fingerprint.service_enumeration import refactored_perform_service_enumeration
from core.fingerprint.web_tech_identification import refactored_perform_web_tech_identification

from core.utils import create_output_directory, record_time

logger = logging.getLogger(__name__)

def validate_target(target, is_domain=True):
    """Valida se o alvo é um domínio ou IP válido."""
    if is_domain:
        # Basic domain validation
        if not target or len(target) > 253:
            return False
        if target.startswith('.') or target.endswith('.'):
            return False
        if '..' in target:
            return False
        # Check for valid characters
        import re
        if not re.match(r'^[a-zA-Z0-9.-]+$', target):
            return False
        return True
    else:
        # IP validation
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            # Try IPv6
            try:
                socket.inet_pton(socket.AF_INET6, target)
                return True
            except socket.error:
                return False

def resolve_domain_to_ips(domain, include_ipv6=False):
    """Resolve domain to IP addresses with error handling."""
    ips = []
    try:
        # Get IPv4 addresses
        ipv4_addresses = socket.getaddrinfo(domain, None, socket.AF_INET)
        for addr_info in ipv4_addresses:
            ip = addr_info[4][0]
            if ip not in ips:
                ips.append(ip)
        
        # Get IPv6 addresses if requested
        if include_ipv6:
            try:
                ipv6_addresses = socket.getaddrinfo(domain, None, socket.AF_INET6)
                for addr_info in ipv6_addresses:
                    ip = addr_info[4][0]
                    if ip not in ips:
                        ips.append(ip)
            except socket.gaierror:
                logger.debug(f"No IPv6 addresses found for {domain}")
                
    except socket.gaierror as e:
        logger.error(f"Failed to resolve domain {domain}: {e}")
    
    return ips

def analyze_target(target_item, is_domain_target, args):
    """Analyze a single target (domain or IP)."""
    start_time_target = time.time()
    
    # Validate target
    if not validate_target(target_item, is_domain_target):
        logger.error(f"Invalid target format: {target_item}")
        return
    
    sanitized_target_name = target_item.replace(':', '_').replace('/', '_')
    logger.info(f"Iniciando análise para o alvo: {target_item} (Tipo: {'Domínio' if is_domain_target else 'IP'})")

    output_base_dir = args.output_dir
    target_output_dir, footprint_dir, fingerprint_dir = create_output_directory(output_base_dir, sanitized_target_name)

    ips_for_fingerprinting = []

    # --- FOOTPRINT MODULE ---
    if args.modulo in ['foot', 'all']:
        logger.info(f"Executando módulo de Footprint para: {target_item}")
        
        try:
            if is_domain_target:
                # Domain-specific footprinting
                perform_whois_lookup(target_item, footprint_dir)
                perform_dns_enumeration(target_item, footprint_dir)
                perform_subdomain_discovery(target_item, footprint_dir)
                
                # IP/ASN mapping will resolve domain to IPs
                ip_asn_data_domain = perform_ip_asn_mapping(target_item, footprint_dir)
                if ip_asn_data_domain:
                    for item in ip_asn_data_domain:
                        if 'ip' in item and item['ip'] not in ips_for_fingerprinting:
                            ips_for_fingerprinting.append(item['ip'])
                
                perform_dns_history(target_item, footprint_dir)
                perform_related_domains(target_item, footprint_dir)
                
                # Geolocation for resolved IPs
                if ips_for_fingerprinting:
                    logger.info(f"Realizando geolocalização para IPs derivados de {target_item}: {ips_for_fingerprinting}")
                    perform_geolocation(target_item, footprint_dir)
                else:
                    # Fallback: try to resolve domain directly
                    resolved_ips = resolve_domain_to_ips(target_item, args.ipv6)
                    if resolved_ips:
                        ips_for_fingerprinting.extend(resolved_ips)
                        perform_geolocation(target_item, footprint_dir)
                    else:
                        logger.warning(f"Could not resolve any IPs for domain {target_item}")

            else:  # IP target
                logger.info(f"Alvo é um IP ({target_item}). Executando footprint específico para IP.")
                ip_asn_data_ip = perform_ip_asn_mapping(target_item, footprint_dir)
                perform_geolocation(target_item, footprint_dir)
                ips_for_fingerprinting.append(target_item)
                
        except Exception as e:
            logger.error(f"Error during footprint analysis for {target_item}: {e}", exc_info=True)

    # Filter IPs based on IPv6 setting
    final_ips_to_scan = []
    if args.ipv6:
        logger.info("Varredura IPv6 habilitada. Incluindo todos os IPs resolvidos.")
        final_ips_to_scan = list(ips_for_fingerprinting)
    else:
        logger.info("Varredura IPv6 desabilitada. Filtrando endereços IPv6.")
        for ip_addr in ips_for_fingerprinting:
            if ':' not in ip_addr:  # Simple IPv4 check
                final_ips_to_scan.append(ip_addr)
            else:
                logger.debug(f"Endereço IPv6 {ip_addr} removido da lista de varredura.")

    # Ensure target IP is included if it's an IP target
    if not is_domain_target and target_item not in final_ips_to_scan:
        final_ips_to_scan.append(target_item)

    if not final_ips_to_scan:
        logger.warning(f"Nenhum IP disponível para fingerprinting do alvo {target_item}.")
        record_time(start_time_target, time.time(), f"Análise completa para {target_item}")
        return

    logger.info(f"IPs finais para fingerprinting: {final_ips_to_scan}")

    # --- FINGERPRINT MODULE ---
    if args.modulo in ['finger', 'all']:
        logger.info(f"Executando módulo de Fingerprint para {target_item} nos IPs: {final_ips_to_scan}")
        
        try:
            # Port scanning
            consolidated_ports_file = os.path.join(fingerprint_dir, "consolidated_open_tcp_ports_by_ip.json")

            if not args.refresh and os.path.exists(consolidated_ports_file):
                logger.info(f"Arquivo de portas consolidadas já existe. Pulando varredura de portas.")
                logger.info("Use a flag --refresh para forçar a re-execução.")
                port_scan_results = {"consolidated_open_ports_by_ip_json_file": consolidated_ports_file}
            else:
                if args.refresh and os.path.exists(consolidated_ports_file):
                    logger.info(f"Flag --refresh detectada. Re-executando varredura de portas.")

                logger.info(f"Executando varredura de portas para {target_item}")
                port_scan_results = perform_port_scanning(
                    target_item, 
                    fingerprint_dir, 
                    ips_list=final_ips_to_scan, 
                    voip=args.voip,
                    fast_mode=getattr(args, 'fast_mode', False)
                )
                consolidated_ports_file = port_scan_results.get("consolidated_open_ports_by_ip_json_file")

            # Service enumeration
            if consolidated_ports_file and os.path.exists(consolidated_ports_file):
                logger.info(f"Iniciando enumeração de serviço baseada em {consolidated_ports_file}")
                service_scan_results_map = refactored_perform_service_enumeration(
                    consolidated_ports_file,
                    fingerprint_dir,
                    original_target_context=target_item,
                    enable_vuln_scan=args.vuln_scan
                )
                
                # Web technology identification
                if service_scan_results_map:
                    logger.info(f"Executando identificação de tecnologias web para {target_item}")
                    refactored_perform_web_tech_identification(
                        service_scan_results_map,
                        fingerprint_dir,
                        original_target_context=target_item
                    )
                else:
                    logger.info(f"Nenhum serviço enumerado para {target_item}")
            else:
                logger.warning(f"Arquivo de portas consolidadas não encontrado para {target_item}")
                
        except Exception as e:
            logger.error(f"Error during fingerprint analysis for {target_item}: {e}", exc_info=True)

    end_time_target = time.time()
    record_time(start_time_target, end_time_target, f"Análise completa para {target_item}")

def run_focused_web_scan(target_host, args):
    """Execute focused web scanning for a specific host."""
    start_time_target = time.time()
    logger.info(f"Iniciando varredura WEB FOCADA para o alvo: {target_host}")

    # Validate target
    if not validate_target(target_host, is_domain=True):
        logger.error(f"Invalid target format: {target_host}")
        return

    # Resolve host to IP
    try:
        resolved_ips = resolve_domain_to_ips(target_host, args.ipv6)
        if not resolved_ips:
            logger.error(f"Could not resolve host '{target_host}'")
            return
        ip_address = resolved_ips[0]  # Use first resolved IP
        logger.info(f"Host '{target_host}' resolvido para o IP: {ip_address}")
    except Exception as e:
        logger.error(f"Error resolving host '{target_host}': {e}")
        return

    # Setup directories
    sanitized_ip_name = ip_address.replace(':', '_').replace('/', '_')
    ip_output_dir, _, ip_fingerprint_dir = create_output_directory(args.output_dir, sanitized_ip_name)

    # Port scanning
    consolidated_ports_file = os.path.join(ip_fingerprint_dir, "consolidated_open_tcp_ports_by_ip.json")
    
    if not args.refresh and os.path.exists(consolidated_ports_file):
        logger.info(f"Resultados de Port Scan para o IP {ip_address} já existem. Reutilizando dados.")
    else:
        logger.info(f"Executando varredura de portas para o IP {ip_address}...")
        perform_port_scanning(
            target_host,
            ip_fingerprint_dir,
            ips_list=[ip_address],
            voip=args.voip,
            fast_mode=True  # Use fast mode for web scans
        )
    
    if not os.path.exists(consolidated_ports_file):
        logger.warning(f"Nenhum arquivo de portas consolidadas gerado para {ip_address}")
        record_time(start_time_target, time.time(), f"Análise web focada para {target_host}")
        return

    # Service enumeration
    logger.info(f"Iniciando enumeração de serviço para o IP {ip_address}")
    service_scan_results_map = refactored_perform_service_enumeration(
        consolidated_ports_file,
        ip_fingerprint_dir,
        original_target_context=target_host,
        enable_vuln_scan=args.vuln_scan
    )

    if not service_scan_results_map:
        logger.warning(f"Nenhum serviço enumerado para o IP {ip_address}")
        record_time(start_time_target, time.time(), f"Análise web focada para {target_host}")
        return

    # Web technology identification
    logger.info(f"Executando análise de tecnologia web para o subdomínio: {target_host}")
    refactored_perform_web_tech_identification(
        service_scan_results_map,
        ip_fingerprint_dir,
        original_target_context=target_host
    )

    record_time(start_time_target, time.time(), f"Análise web focada completa para {target_host}")

def main():
    parser = argparse.ArgumentParser(
        description="Automatiza a análise de segurança de domínios e IPs.", 
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Target input group
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--dominios", help="Lista de domínios separados por vírgula (ex: dominio1.com,dominio2.net)")
    target_group.add_argument("--ips", help="Lista de IPs separados por vírgula (ex: 1.1.1.1,8.8.8.8,2001:db8::1)")
    
    # Execution mode group
    mode_group = parser.add_argument_group('Modo de Execução')
    mode_exclusive_group = mode_group.add_mutually_exclusive_group()
    mode_exclusive_group.add_argument("--modulo", default="all", choices=['foot', 'finger', 'all'], 
                                       help="Módulo de análise completa: foot, finger ou all. Padrão: all")
    mode_exclusive_group.add_argument("--web-scan", action="store_true", default=False,
                                       help="MODO RÁPIDO: Executa uma varredura focada apenas em serviços web.")
    
    # Configuration options
    parser.add_argument("--verbose", default="INFO", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], 
                        help="Nível de verbosidade do logging. Padrão: INFO")
    parser.add_argument("--threads", type=int, default=5, 
                        help="Número máximo de threads paralelas. Padrão: 5")
    parser.add_argument("--output_dir", default="output", 
                        help="Diretório base para salvar os resultados. Padrão: output")
    parser.add_argument("--log_file", default="logs/script.log", 
                        help="Arquivo de log. Padrão: logs/script.log")
    
    # Scanning options
    parser.add_argument("--voip", action="store_true", default=False,
                        help="Habilita a varredura de portas UDP para VoIP. Padrão: Desabilitado.")
    parser.add_argument("--ipv6", action="store_true", default=False,
                        help="Habilita a varredura de endereços IPv6. Padrão: Desabilitado.")
    parser.add_argument("--refresh", action="store_true", default=False,
                        help="Força a re-execução de todas as etapas, ignorando resultados existentes.")
    parser.add_argument("--vuln-scan", action="store_true", default=False,
                        help="Habilita a varredura de vulnerabilidades com Nmap (--script=vuln). INTRUSIVO e lento.")

    args = parser.parse_args()
    
    # Setup logging
    os.makedirs(os.path.dirname(args.log_file), exist_ok=True)
    logger = setup_logging(level=args.verbose, log_file=args.log_file)

    # Determine target list and type
    if args.dominios:
        target_list = [d.strip() for d in args.dominios.split(',') if d.strip()]
        is_domain_input = True
        logger.info(f"Script iniciado para DOMÍNIOS: {target_list}")
    elif args.ips:
        target_list = [ip.strip() for ip in args.ips.split(',') if ip.strip()]
        is_domain_input = False
        logger.info(f"Script iniciado para IPs: {target_list}")
    else:
        logger.error("Nenhum alvo especificado")
        sys.exit(1)

    # Validate all targets
    invalid_targets = []
    for target in target_list:
        if not validate_target(target, is_domain_input):
            invalid_targets.append(target)
    
    if invalid_targets:
        logger.error(f"Alvos inválidos detectados: {invalid_targets}")
        sys.exit(1)

    # Log configuration
    logger.info("=== MMCyberSec - Análise de Segurança Iniciada ===")
    logger.info(f"Tipo de entrada: {'Domínios' if is_domain_input else 'IPs'}")
    logger.info(f"Módulo selecionado: {args.modulo if not args.web_scan else 'web-scan'}")
    logger.info(f"Threads máximas: {args.threads}")
    logger.info(f"Varredura VoIP: {'Habilitada' if args.voip else 'Desabilitada'}")
    logger.info(f"Varredura IPv6: {'Habilitada' if args.ipv6 else 'Desabilitada'}")
    logger.info(f"Varredura de vulnerabilidades: {'Habilitada' if args.vuln_scan else 'Desabilitada'}")
    logger.info(f"Refresh mode: {'Habilitado' if args.refresh else 'Desabilitado'}")
    logger.info(f"Alvos: {target_list}")

    # Execute analysis
    try:
        if args.web_scan:
            if not args.dominios:
                parser.error("--web-scan requer --dominios para especificar subdomínios alvo.")
            
            logger.info("Modo RÁPIDO ativado: Executando varredura focada em serviços web.")
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = [executor.submit(run_focused_web_scan, target_item, args) for target_item in target_list]
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Erro durante análise web: {e}", exc_info=True)
        else:
            # Full analysis mode
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = [executor.submit(analyze_target, target_item, is_domain_input, args) for target_item in target_list]
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Erro durante análise completa: {e}", exc_info=True)

        logger.info("=== Análise de todos os alvos concluída ===")
        
    except KeyboardInterrupt:
        logger.info("Análise interrompida pelo usuário")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Erro crítico durante execução: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()