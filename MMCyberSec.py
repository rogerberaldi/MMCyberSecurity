import argparse
import logging
import os
import concurrent.futures
import time
import socket


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

# Em MMCyberSec.py

# Renomear analyze_domain para analyze_target
def analyze_target(target_item, is_domain_target, args): # Novo parâmetro is_domain_target
    start_time_target = time.time()
    
    # Sanitizar o nome do alvo para criar diretórios (útil para IPs com ':')
    sanitized_target_name = target_item.replace(':', '_').replace('/', '_')
    logger.info(f"Iniciando análise para o alvo: {target_item} (Tipo: {'Domínio' if is_domain_target else 'IP'})")

    output_base_dir = args.output_dir
    # create_output_directory pode continuar usando sanitized_target_name
    target_output_dir, footprint_dir, fingerprint_dir = create_output_directory(output_base_dir, sanitized_target_name)

    ips_for_fingerprinting = []

    # --- MÓDULO DE FOOTPRINT ---
    if args.modulo in ['foot', 'all']:
        logger.info(f"Executando módulo de Footprint para: {target_item}")
        if is_domain_target:
            # Footprinting específico para domínios
            perform_whois_lookup(target_item, footprint_dir) #
            perform_dns_enumeration(target_item, footprint_dir) #
            perform_subdomain_discovery(target_item, footprint_dir) #
            
            # perform_ip_asn_mapping irá resolver o domínio para IPs e coletar informações
            ip_asn_data_domain = perform_ip_asn_mapping(target_item, footprint_dir) #
            if ip_asn_data_domain:
                for item in ip_asn_data_domain:
                    if 'ip' in item and item['ip'] not in ips_for_fingerprinting:
                        ips_for_fingerprinting.append(item['ip'])
            
            perform_dns_history(target_item, footprint_dir) #
            perform_related_domains(target_item, footprint_dir) #
            

            if ips_for_fingerprinting:
                
                 logger.info(f"Realizando geolocalização para IPs derivados de {target_item}: {ips_for_fingerprinting}")
                 perform_geolocation(ips_for_fingerprinting, footprint_dir) # perform_geolocation precisa aceitar IP
            else:
                try:
                    ip_address = socket.gethostbyname(target_item)
                    perform_geolocation(target_item, footprint_dir) 
                except Exception as e:
                    logger.warning(f"Não foi possível resolver o IP para o domínio {e}: {target_item}")
                 

        else: # O alvo é um IP
            # Footprinting específico para IPs
            logger.info(f"Alvo é um IP ({target_item}). Alguns módulos de footprint de domínio serão pulados ou adaptados.")
            # perform_ip_asn_mapping para um IP irá buscar informações sobre esse IP.
            ip_asn_data_ip = perform_ip_asn_mapping(target_item, footprint_dir) #
            # Não precisa popular ips_for_fingerprinting aqui, faremos isso depois.
            
            perform_geolocation(target_item, footprint_dir) #
            # Módulos como whois (em IP pode ser diferente), subdomain_discovery, dns_history (baseado em domínio), related_domains não são diretamente aplicáveis
            # ou retornam informações diferentes para IPs. Você pode adicionar chamadas específicas se desejar (ex: PTR lookup em dns_enumeration).

    final_ips_to_scan = []
    
    if args.ipv6:
        logger.info("Varredura IPv6 habilitada. Incluindo todos os IPs resolvidos.")
        final_ips_to_scan = list(ips_for_fingerprinting) # Usar uma cópia
    else:
        logger.info("Varredura IPv6 desabilitada. Filtrando endereços IPv6.")
        for ip_addr in ips_for_fingerprinting:
            if ':' not in ip_addr:  # Checagem simples para identificar IPv4
                final_ips_to_scan.append(ip_addr)
            else:
                logger.debug(f"Endereço IPv6 {ip_addr} removido da lista de varredura.")

    if not final_ips_to_scan:
        logger.warning(f"Nenhum IP (após filtro IPv6) para fingerprinting do alvo {target_item}.")
    else:
        logger.info(f"IPs finais para fingerprinting (após filtro IPv6): {final_ips_to_scan}")

    # --- PREPARAÇÃO DE IPs PARA FINGERPRINTING ---
    if is_domain_target:
        # Se o alvo era um domínio, final_ips_to_scan já foi populado (ou está vazio se não houve resolução).
        if not final_ips_to_scan and args.modulo in ['finger', 'all']: # Se fingerprinting é desejado mas não temos IPs
            logger.warning(f"Nenhum IP resolvido durante o footprint para o domínio {target_item}. Tentando resolver novamente para fingerprinting.")
            # Tenta resolver novamente caso o módulo 'foot' não tenha sido 'all' ou falhou em popular
            ip_asn_data_retry = perform_ip_asn_mapping(target_item, footprint_dir)
            if ip_asn_data_retry:
                for item in ip_asn_data_retry:
                    if 'ip' in item and item['ip'] not in final_ips_to_scan:
                        if args.ipv6:
                            final_ips_to_scan.append(item['ip'])
                        else:
                            if ':' not in item['ip']:
                                final_ips_to_scan.append(item['ip'])

    else: # O alvo já é um IP
        if target_item not in final_ips_to_scan: # Garante que o IP alvo original esteja na lista para fingerprint
            final_ips_to_scan.append(target_item)

    service_scan_results_map = {} # Para armazenar os caminhos dos XMLs de serviço por IP

    # --- MÓDULO DE FINGERPRINT ---
    if args.modulo in ['finger', 'all']:
        if not final_ips_to_scan:
            logger.warning(f"Nenhum IP disponível para fingerprinting do alvo {target_item}. Pulando módulo Fingerprint.")
        else:
            logger.info(f"Executando módulo de Fingerprint para {target_item} nos IPs: {final_ips_to_scan}")
            # Inicializa as variáveis de resultado
            port_scan_results = {}
            service_scan_results_map = {}

            consolidated_ports_file = os.path.join(fingerprint_dir, "consolidated_open_tcp_ports_by_ip.json")

            if not args.refresh and os.path.exists(consolidated_ports_file):
                logger.info(f"Arquivo de portas consolidadas já existe em '{consolidated_ports_file}'. Pulando varredura de portas.")
                logger.info("Use a flag --refresh para forçar a re-execução desta etapa.")

                # Popula o dicionário de resultados com o caminho do arquivo existente para as próximas etapas
                port_scan_results["consolidated_open_ports_by_ip_json_file"] = consolidated_ports_file
            else:
                if args.refresh and os.path.exists(consolidated_ports_file):
                    logger.info(f"Flag --refresh detectada. Re-executando varredura de portas para {target_item}.")

                logger.info(f"Executando varredura de portas para {target_item} nos IPs: {final_ips_to_scan}")
                port_scan_results = perform_port_scanning(target_item, fingerprint_dir, ips_list=final_ips_to_scan, voip=args.voip)
                consolidated_ports_file = port_scan_results.get("consolidated_open_ports_by_ip_json_file") 

            if consolidated_ports_file and os.path.exists(consolidated_ports_file):
                logger.info(f"Iniciando enumeração de serviço Nmap baseada em {consolidated_ports_file} para {target_item}")
                # fingerprint_dir é o diretório base para este alvo (ex: output/alvo/fingerprint)
                service_scan_results_map = refactored_perform_service_enumeration(
                                            consolidated_ports_file,
                                            fingerprint_dir, # Os resultados por IP serão salvos em subdirs de fingerprint_dir
                                            original_target_context=target_item,
                                            enable_vuln_scan=args.vuln_scan
                                        ) # Passa o caminho do JSON e o diretório base para salvar os XMLs de serviço
                if service_scan_results_map:
                    logger.info(f"Resultados da enumeração de serviço Nmap (mapa IP->XML): {service_scan_results_map}")
                    final_web_tech_file = os.path.join(fingerprint_dir, "web_technologies_consolidated.json")
                    if not args.refresh and os.path.exists(final_web_tech_file):
                        logger.info(f"Arquivo de tecnologias web consolidado já existe: '{final_web_tech_file}'. Pulando etapa.")
                        logger.info("Use a flag --refresh para forçar a re-execução.")
                    else:
                        pass
                        # A função agora recebe o mapa de resultados do scan de serviço
                        #refactored_perform_web_tech_identification(service_scan_results_map,fingerprint_dir,original_target_context=target_item)
                else:
                    logger.info(f"Nenhum resultado da enumeração de serviço Nmap para {target_item}.")
            elif port_scan_results.get("rustscan_ports_by_ip"): # Fallback se o arquivo JSON não foi criado mas temos o mapa
                logger.warning(f"Arquivo open_ports_by_ip.json não encontrado, mas dados do Rustscan existem. Tentando usar dados em memória (ISSO NÃO DEVERIA ACONTECER REGULARMENTE).")
                # Esta parte é um fallback e idealmente não seria necessária se save_json sempre funcionar.
                # E refactored_perform_service_enumeration espera um *caminho de arquivo*.
                # Para simplificar, vamos focar no fluxo onde o arquivo JSON existe.
                # Se você precisar de um fallback para dados em memória, refactored_perform_service_enumeration precisaria de outra adaptação.
                logger.error(f"Não foi possível encontrar {consolidated_ports_file}, e o fallback para dados em memória não está implementado diretamente em refactored_perform_service_enumeration. Enumeração de serviço pulada.")
            
            else:
                logger.info(f"Nenhuma porta aberta (via Rustscan/JSON) para executar enumeração de serviço para {target_item}.")

            # AGORA, service_scan_results_map contém {"ip": "caminho_para_o_xml_de_servico_do_ip.xml"}
            # Este mapa será o INPUT para a refatoração de perform_web_tech_identification.
            # IMPORTANTE: As funções perform_service_enumeration e perform_web_tech_identification
            # precisarão de refatoração significativa para lidar com os resultados por IP de port_scan_results.
            # Ex: port_scan_results["rustscan_ports_by_ip"] é um dicionário IP -> [portas]
            #     port_scan_results["nmap_tcp_scan_outputs"] é IP -> caminho_xml

            if port_scan_results and port_scan_results.get("rustscan_ports_by_ip"):
                 logger.info("Integração de 'perform_service_enumeration' com resultados por IP pendente.")
                 # Exemplo conceitual (requer refatoração de perform_service_enumeration):
                 # refactored_perform_service_enumeration(
                 #    port_scan_results["rustscan_ports_by_ip"], 
                 #    fingerprint_dir, 
                 #    target_item # para contexto
                 # )
                 pass # Substituir pelo código refatorado
            else:
                 logger.info(f"Nenhuma porta aberta (via Rustscan) para executar enumeração de serviço para {target_item}.")

            logger.info("Integração de 'perform_web_tech_identification' com resultados por IP pendente.")
            # perform_web_tech_identification(target_item, fingerprint_dir, final_ips_to_scan) # Pode precisar dos IPs e dos XMLs de Nmap por IP
            pass # Substituir pelo código refatorado

    end_time_target = time.time()
    record_time(start_time_target, end_time_target, f"Análise completa para {target_item}")



def run_focused_web_scan(target_host, args):
    """
    Executa um fluxo de análise web granular e eficiente para um host/subdomínio.
    Reutiliza scans de porta/serviço de IP existentes sempre que possível.
    """
    start_time_target = time.time()
    logger.info(f"Iniciando varredura WEB FOCADA para o alvo: {target_host}")

    # --- ETAPA 1: SETUP E RESOLUÇÃO DE IP ---
    try:
        ip_address = socket.gethostbyname(target_host)
        logger.info(f"Host '{target_host}' resolvido para o IP: {ip_address}")
    except socket.gaierror as e:
        logger.error(f"Não foi possível resolver o host '{target_host}': {e}")
        return

    # Padroniza nomes de diretório para IP e Host. Usaremos o diretório do IP como base para resultados de infra.
    sanitized_ip_name = ip_address.replace(':', '_').replace('/', '_')
    ip_output_dir, _, ip_fingerprint_dir = create_output_directory(args.output_dir, sanitized_ip_name)

    # --- ETAPA 2: OBTER DADOS DE PORTAS DO IP (EXECUTAR SCAN APENAS SE NECESSÁRIO) ---
    consolidated_ports_file = os.path.join(ip_fingerprint_dir, "consolidated_open_tcp_ports_by_ip.json")
    
    if not args.refresh and os.path.exists(consolidated_ports_file):
        logger.info(f"Resultados de Port Scan para o IP {ip_address} já existem. Reutilizando dados de '{consolidated_ports_file}'.")
    else:
        logger.info(f"Nenhum resultado de Port Scan encontrado para o IP {ip_address} (ou --refresh ativado). Executando varredura de portas completa...")
        # A saída de perform_port_scanning (incluindo o JSON consolidado) será salva em ip_fingerprint_dir
        perform_port_scanning(
            target_host,          # Passa o host original para contexto de logging
            ip_fingerprint_dir,   # Salva os resultados no diretório do IP
            ips_list=[ip_address],
            voip=args.voip
        )
    
    # Se o arquivo ainda não existir (ex: scan falhou ou não encontrou portas), não podemos continuar.
    if not os.path.exists(consolidated_ports_file):
        logger.warning(f"Varredura de portas concluída, mas nenhum arquivo de portas consolidadas foi gerado para {ip_address}. Finalizando análise para {target_host}.")
        record_time(start_time_target, time.time(), f"Análise web focada concluída (sem portas) para {target_host}")
        return

    # --- ETAPA 3: OBTER DADOS DE SERVIÇOS DO IP (EXECUTAR SCAN APENAS SE NECESSÁRIO) ---
    # Precisamos de uma forma de saber se a enumeração de serviço já foi feita.
    # Podemos verificar a existência dos arquivos XML de serviço.
    service_scan_results_map = {}
    service_enum_needed = True

    if not args.refresh:
        # Lógica para verificar se os scans de serviço já existem
        # Por simplicidade, vamos assumir que se o primeiro arquivo XML esperado existir, todos existem.
        # Uma lógica mais robusta poderia verificar todos.
        # Para este exemplo, vamos manter o fluxo de re-executar se a etapa final (web scan) não estiver pronta.
        # A lógica de pular a enumeração de serviço pode ser adicionada depois se necessário.
        pass

    logger.info(f"Iniciando enumeração de serviço Nmap para o IP {ip_address} (baseado em {consolidated_ports_file})")
    service_scan_results_map = refactored_perform_service_enumeration(
        consolidated_ports_file,
        ip_fingerprint_dir, # Os XMLs de serviço serão salvos no diretório do IP
        original_target_context=target_host,
        enable_vuln_scan=args.vuln_scan
    )

    if not service_scan_results_map:
        logger.warning(f"Nenhum serviço pôde ser enumerado para o IP {ip_address}. Não é possível prosseguir com a análise web para {target_host}.")
        record_time(start_time_target, time.time(), f"Análise web focada concluída (sem serviços enumerados) para {target_host}")
        return

    # --- ETAPA 4: EXECUTAR ANÁLISE WEB (ESPECÍFICA PARA O SUBDOMÍNIO) ---
    # Esta etapa deve sempre ser executada para o target_host, pois é a análise de aplicação.
    logger.info(f"Executando análise de tecnologia e vulnerabilidades web direcionada para o SUBDOMÍNIO: {target_host}")
    refactored_perform_web_tech_identification(
        service_scan_results_map,
        ip_fingerprint_dir, # O diretório base ainda é o do IP
        original_target_context=target_host # Passa o subdomínio para ser usado nos scans web
    )

    record_time(start_time_target, time.time(), f"Análise web focada completa para {target_host}")

def old_run_focused_web_scan(target_host, args):
    """
    Executa um fluxo de fingerprint COMPLETO focado em análise web para um único host.
    1. Resolve o host para IP.
    2. Verifica se resultados completos já existem (a menos que --refresh seja usado).
    3. Executa a varredura COMPLETA de todas as portas TCP.
    4. Executa a enumeração de serviços nas portas encontradas.
    5. Executa a identificação de tecnologias e vulnerabilidades web.
    """
    start_time_target = time.time()

    # 3. Resolver Host para IP (etapa necessária para todas as ferramentas baseadas em IP)
    try:
        ip_address = socket.gethostbyname(target_host)
        logger.info(f"Host '{target_host}' resolvido para o IP: {ip_address}")
    except socket.gaierror as e:
        logger.error(f"Não foi possível resolver o host '{target_host}': {e}")
        return
    
    sanitized_target_name = target_host.replace(':', '_').replace('/', '_')
    sanitized_target_ip = ip_address.replace(':', '_').replace('/', '_')
    logger.info(f"Iniciando varredura WEB COMPLETA para o alvo: {target_host} (IP: {ip_address})")

    target_output_dir, footprint_dir, fingerprint_dir_ip = create_output_directory(args.output_dir, sanitized_target_ip)
    consolidated_ports_file = os.path.join(fingerprint_dir_ip, "consolidated_open_tcp_ports_by_ip.json")

    target_output_dir, footprint_dir, fingerprint_dir = create_output_directory(args.output_dir, sanitized_target_name)
    
    port_scan_results = {}

    if not args.refresh and os.path.exists(consolidated_ports_file):
        logger.info(f"Arquivo de portas consolidadas já existe em '{consolidated_ports_file}'. Pulando varredura de portas. Usando resultados existentes.")
        logger.info("Use a flag --refresh para forçar a re-execução desta etapa.")

        # Popula o dicionário de resultados com o caminho do arquivo existente para as próximas etapas
        port_scan_results["consolidated_open_ports_by_ip_json_file"] = consolidated_ports_file

    else:
        # 2. Lógica Inteligente de "Skip" baseada em sua sugestão
        # Verificamos a existência do arquivo de resultado final desta análise.
        final_web_tech_file = os.path.join(fingerprint_dir, "web_technologies_consolidated.json")
        if not args.refresh and os.path.exists(final_web_tech_file):
            logger.info(f"Resultado completo da varredura web já existe para '{target_host}' em '{final_web_tech_file}'.")
            logger.info("Pulando varredura. Use a flag --refresh para forçar a re-execução.")
            record_time(start_time_target, time.time(), f"Varredura web focada pulada (resultados existentes) para {target_host}")
            return

        # 4. Executar a Varredura COMPLETA de Portas (Reutilizando a função principal)
        # Esta função já executa Rustscan, Masscan, e Nmap -sT, e consolida os resultados.
        logger.info(f"Executando varredura de portas completa para {target_host} ({ip_address}) para encontrar todos os serviços...")
        port_scan_results = perform_port_scanning(
            target_host, 
            fingerprint_dir_ip, 
            ips_list=[ip_address],
            voip=args.voip
        )

    # 5. Executar Enumeração de Serviço nos Resultados Consolidados
    service_scan_results_map = {}
    consolidated_ports_file = port_scan_results.get("consolidated_open_ports_by_ip_json_file")
    
    if consolidated_ports_file:
        logger.info(f"Iniciando enumeração de serviço Nmap baseada em {consolidated_ports_file} para {target_host}")
        service_scan_results_map = refactored_perform_service_enumeration(
            consolidated_ports_file,
            fingerprint_dir,
            original_target_context=target_host,
            enable_vuln_scan=args.vuln_scan # Respeita a flag --vuln-scan
        )
    else:
        logger.warning(f"Nenhuma porta aberta encontrada na varredura completa para {target_host}. Não é possível prosseguir com a análise web.")
        record_time(start_time_target, time.time(), f"Análise web focada concluída (sem portas abertas) para {target_host}")
        return

    # 6. Executar Identificação de Tecnologias e Vulnerabilidades Web
    if service_scan_results_map:
        logger.info(f"Serviços enumerados. Prosseguindo com a análise de tecnologia e vulnerabilidades web para {target_host}.")
        refactored_perform_web_tech_identification(
            service_scan_results_map,
            fingerprint_dir,
            original_target_context=target_host
        )
    else:
        logger.warning(f"Nenhum serviço pode ser enumerado para {target_host}. Não é possível prosseguir com a análise web.")

    record_time(start_time_target, time.time(), f"Análise web focada completa para {target_host}")

def main():
    parser = argparse.ArgumentParser(description="Automatiza a análise de segurança de domínios.", formatter_class=argparse.RawTextHelpFormatter)
    
    
    # Grupo para entrada de alvos mutuamente exclusiva
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--dominios", help="Lista de domínios separados por vírgula (ex: dominio1.com,dominio2.net)")
    target_group.add_argument("--ips",      help="Lista de IPs separados por vírgula (ex: 1.1.1.1,8.8.8.8,2001:db8::1)")
    
    #parser.add_argument("--dominios", required=True, help="Lista de domínios separados por vírgula (ex: dominio1.com,dominio2.net)")
    #parser.add_argument("--modulo", 
    #                    default="all", 
    #                    choices=['foot', 'finger', 'all'], 
    #                    help="Módulo a ser executado: foot (Footprint), finger (Fingerprint) ou all (Ambos). Padrão: all")
    # Grupo para modo de execução
    mode_group = parser.add_argument_group('Modo de Execução')
    mode_exclusive_group = mode_group.add_mutually_exclusive_group()
    mode_exclusive_group.add_argument("--modulo", default="all", choices=['foot', 'finger', 'all'], 
                                       help="Módulo de análise completa: foot, finger ou all. Padrão: all")
    mode_exclusive_group.add_argument("--web-scan", action="store_true", default=False,
                                       help="MODO RÁPIDO: Executa uma varredura focada apenas em serviços web no(s) alvo(s) especificado(s).")
    
    parser.add_argument("--verbose", 
                        default="INFO", 
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], 
                        help="Nível de verbosidade do logging. Padrão: INFO")
    
    parser.add_argument("--threads", 
                        type=int, 
                        default=5, 
                        help="Número máximo de threads paralelas. Padrão: 5")
    
    parser.add_argument("--output_dir", 
                        default="output", 
                        help="Diretório base para salvar os resultados. Padrão: output")
    
    parser.add_argument("--log_file", 
                        default="logs/script.log", 
                        help="Arquivo de log. Padrão: logs/script.log")
    
    parser.add_argument("--voip", action="store_true", default=False,
                    help="Habilita a varredura de portas UDP para VoIP. Padrão: Desabilitado.")
                         
    parser.add_argument("--ipv6", action="store_true", default=False,
                    help="Habilita a varredura de endereços IPv6. "
                         "Requer configuração IPv6 na interface de origem. Padrão: Desabilitado.")
    
    parser.add_argument("--refresh", action="store_true", default=False,
                    help="Força a re-execução de todas as etapas de varredura, "
                         "ignorando resultados previamente salvos.")

    parser.add_argument("--vuln-scan", action="store_true", default=False,
                    help="Habilita a varredura de vulnerabilidades com Nmap (--script=vuln) "
                         "durante a enumeração de serviço. "
                         "Esta etapa é INTRUSIVA e pode ser lenta.")

    args = parser.parse_args()
    logger = setup_logging(level=args.verbose, log_file=args.log_file)

    if args.dominios:
        target_list = [d.strip() for d in args.dominios.split(',')]
        is_domain_input = True
        logger.info(f"Script de análise iniciado para DOMÍNIOS: {target_list}")

    elif args.ips:
        target_list = [ip.strip() for ip in args.ips.split(',')]
        is_domain_input = False
        logger.info(f"Script de análise iniciado para IPs: {target_list}")

    logger.info("Script de análise de segurança de domínios iniciado.")
    logger.info(f"Tipo de entrada: {'Domínios' if is_domain_input else 'IPs'}")
    logger.info(f"Nível de verbosidade: {args.verbose}")
    logger.info(f"Módulo selecionado: {args.modulo}")
    logger.info(f"Threads máximas: {args.threads}")
    logger.info(f"Varredura VoIP: {'Habilitada' if args.ipv6 else 'Desabilitada'}")
    logger.info(f"Varredura IPv6: {'Habilitada' if args.ipv6 else 'Desabilitada'}")
    logger.info(f"Diretório de output: {args.output_dir}")
    logger.info(f"Arquivo de log: {args.log_file}")
    logger.info(f"Alvo(s): {target_list}")

    if args.refresh:
        logger.info("Flag --refresh detectada. Todas as etapas de varredura serão re-executadas.")

    if args.vuln_scan:
        logger.info("Varredura de vulnerabilidades com Nmap (--script=vuln) habilitada. "
                    "Esta etapa é INTRUSIVA e pode ser lenta.")
    if args.web_scan:
        if not args.dominios:
            parser.error("--web-scan é melhor utilizado com --dominios para especificar o(s) subdomínio(s) alvo.")      
        logger.info("Modo RÁPIDO ativado: Executando varredura focada em serviços web.")
        
        target_list = [d.strip() for d in args.dominios.split(',')]

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = [executor.submit(run_focused_web_scan, target_item, args) for target_item in target_list]
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Erro durante a análise de um dos alvos: {e}", exc_info=True) # exc_info=True para traceback

    else:
        target_list = []
        is_domain_input = False # Flag para saber o tipo de entrada

        if args.dominios:
            target_list = [d.strip() for d in args.dominios.split(',')]
            is_domain_input = True

        elif args.ips:
            target_list = [ip.strip() for ip in args.ips.split(',')]


        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = [executor.submit(analyze_target, target_item, is_domain_input, args) for target_item in target_list]
            #futures = [executor.submit(analyze_domain, domain, args) for domain in domains]
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Erro durante a análise de um dos alvos: {e}", exc_info=True) # exc_info=True para traceback

    logger.info("Análise de todos os domínios concluída.")
    
if __name__ == "__main__":
    main()
