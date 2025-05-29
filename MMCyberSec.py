import argparse
import logging
import os
import concurrent.futures
import time

from core.logging_config import setup_logging

from core.footprint.whois_lookup import perform_whois_lookup
from core.footprint.dns_enumeration import perform_dns_enumeration
from core.footprint.subdomain_discovery import perform_subdomain_discovery
from core.footprint.ip_asn_mapping import perform_ip_asn_mapping
from core.footprint.dns_history import perform_dns_history
from core.footprint.geolocation import perform_geolocation
from core.footprint.related_domains import perform_related_domains

from core.fingerprint.port_scanning import perform_port_scanning
from core.fingerprint.service_enumeration import perform_service_enumeration
from core.fingerprint.web_tech_identification import perform_web_tech_identification

from core.utils import create_output_directory, record_time

logger = logging.getLogger(__name__)

def analyze_domain(domain, args):
    """Função principal para analisar um único domínio."""
    start_time_domain = time.time()
    logger.info(f"Iniciando análise para o domínio: {domain}")

    output_base_dir = args.output_dir
    domain_dir, footprint_dir, fingerprint_dir = create_output_directory(output_base_dir, domain)
 
    if args.modulo in ['foot', 'all']:
        logger.info(f"Executando módulo de Footprint para: {domain}")
        perform_whois_lookup(domain, footprint_dir)
        perform_dns_enumeration(domain, footprint_dir) 
        perform_subdomain_discovery(domain, footprint_dir)
        ip_asn_data = perform_ip_asn_mapping(domain, footprint_dir)
        ips = []
        if ip_asn_data:
            for item in ip_asn_data:
                if 'ip' in item:
                    ips.append(item['ip'])
        
        logger.info(f"IPs encontrados: {ips}")
        #ips = ["192.168.1.64","192.168.1.116"]

        perform_dns_history(domain, footprint_dir) 
        perform_geolocation(domain, footprint_dir) 
        perform_related_domains(domain, footprint_dir)

    if args.modulo in ['finger', 'all']:
        logger.info(f"Executando módulo de Fingerprint para: {domain}")
        # Adicionaremos os módulos de Fingerprint aqui
        port_scan_results = perform_port_scanning(domain, fingerprint_dir, list(ips)) 
        if port_scan_results and port_scan_results.get('open_ports'):
            perform_service_enumeration(domain, fingerprint_dir) # Executa apenas se houver portas aberta
        perform_web_tech_identification(domain, fingerprint_dir) # Adicionamos esta linha


    end_time_domain = time.time()
    record_time(start_time_domain, end_time_domain, f"Análise completa para {domain}")

def main():
    parser = argparse.ArgumentParser(description="Automatiza a análise de segurança de domínios.")
    parser.add_argument("--dominios", required=True, help="Lista de domínios separados por vírgula (ex: dominio1.com,dominio2.net)")
    parser.add_argument("--modulo", default="all", choices=['foot', 'finger', 'all'], help="Módulo a ser executado: foot (Footprint), finger (Fingerprint) ou all (Ambos). Padrão: all")
    parser.add_argument("--verbose", default="INFO", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], help="Nível de verbosidade do logging. Padrão: INFO")
    parser.add_argument("--threads", type=int, default=5, help="Número máximo de threads paralelas. Padrão: 5")
    parser.add_argument("--output_dir", default="output", help="Diretório base para salvar os resultados. Padrão: output")
    parser.add_argument("--log_file", default="logs/script.log", help="Arquivo de log. Padrão: logs/script.log")

    args = parser.parse_args()

    logger = setup_logging(level=args.verbose, log_file=args.log_file)
    logger.info("Script de análise de segurança de domínios iniciado.")
    logger.info(f"Nível de verbosidade: {args.verbose}")
    logger.info(f"Módulo selecionado: {args.modulo}")
    logger.info(f"Threads máximas: {args.threads}")
    logger.info(f"Diretório de output: {args.output_dir}")
    logger.info(f"Arquivo de log: {args.log_file}")

    domains = [domain.strip() for domain in args.dominios.split(',')]
    logger.info(f"Domínios alvo: {domains}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(analyze_domain, domain, args) for domain in domains]
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.error(f"Erro durante a análise: {e}")

    logger.info("Análise de todos os domínios concluída.")

if __name__ == "__main__":
    main()
