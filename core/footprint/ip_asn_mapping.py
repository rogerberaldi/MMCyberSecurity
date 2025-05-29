import logging
import time
import os
from core.utils import execute_command, save_json, record_time
from ipwhois import IPWhois
import json

logger = logging.getLogger(__name__)

def get_ip_info_ipwhois(ip_address):
    """Obtém informações de IP e ASN usando ipwhois."""
    try:
        obj = IPWhois(ip_address)
        results = obj.lookup_rdap(depth=1)
        network_info = results.get('network')

        asn_date_str = str(results.get('asn_date')) if results.get('asn_date') else None

        return {
            "ip": ip_address,
            "asn": results.get('asn'),
            "asn_cidr": results.get('asn_cidr'),
            "asn_country_code": results.get('asn_country_code'),
            "asn_date": str(results.get('asn_date')),
            "asn_registry": results.get('asn_registry'),
            "network": network_info,
            "objects": results.get('objects', {})
        }
    except Exception as e:
        logger.warning(f"Erro ao obter informações de IP com ipwhois para {ip_address}: {e}")
        return {"ip": ip_address, "error": str(e)}

def get_ip_info_whois_cli(ip_address):
    """Obtém informações de IP usando o comando whois."""
    command = ["whois", ip_address]
    stdout, stderr, returncode = execute_command(command)
    if returncode == 0:
        return {"ip": ip_address, "whois_output": stdout}
    else:
        logger.warning(f"Erro ao obter informações de IP com whois para {ip_address}: {stderr}")
        return {"ip": ip_address, "error": stderr}

def perform_ip_asn_mapping(domain, output_dir):
    """Realiza o mapeamento de IP e ASN para o domínio."""
    start_time = time.time()
    logger.info(f"Iniciando mapeamento de IP e ASN para: {domain}")

    ip_asn_data = []
    ips = set()

    if os.path.exists(f"{output_dir}/ip_asn.json"):
        logger.info(f"Arquivo de mapeamento de IP ASN já existe: {output_dir}/ip_asn.json")
        with open(f"{output_dir}/ip_asn.json", 'r') as f:
            ip_asn_data = json.load(f)
        return ip_asn_data



    # Tenta obter o endereço IP do domínio
    try:
        import socket
        ip_address = socket.gethostbyname(domain)
        ips.add(ip_address)
    except socket.gaierror:
        logger.warning(f"Não foi possível resolver o IP para o domínio: {domain}")

    # Tenta obter IPs dos registros A e AAAA (se disponíveis)
    try:
        from dns.resolver import resolve
        for record_type in ['A', 'AAAA']:
            answers = resolve(domain, record_type)
            for rdata in answers:
                ips.add(str(rdata))
    except Exception as e:
        logger.debug(f"Erro ao obter registros A/AAAA para {domain}: {e}")

    # Obtém IPs dos subdomínios descobertos (se houver)
    subdomains_file = f"{output_dir}/all_subdomains.txt"
    if os.path.exists(subdomains_file):
        with open(subdomains_file, 'r') as f:
            for subdomain in f:
                subdomain = subdomain.strip()
                try:
                    ip_address = socket.gethostbyname(subdomain)
                    ips.add(ip_address)
                except socket.gaierror:
                    logger.debug(f"Não foi possível resolver o IP para o subdomínio: {subdomain}")

    for ip in sorted(list(ips)):
        logger.info(f"Obtendo informações de IP para: {ip}")
        ip_info_ipwhois = get_ip_info_ipwhois(ip)
        # ip_info_whois_cli = get_ip_info_whois_cli(ip) # Opcional: pode gerar saída muito verbosa
        ip_asn_data.append(ip_info_ipwhois) # + [ip_info_whois_cli])

    end_time = time.time()
    record_time(start_time, end_time, f"Mapeamento de IP e ASN para {domain}")
    save_json(ip_asn_data, f"{output_dir}/ip_asn.json")
    logger.info(f"Mapeamento de IP e ASN para {domain} concluído. Resultados salvos em: {output_dir}/ip_asn.json")
    return ip_asn_data

if __name__ == '__main__':
    from core.logging_config import setup_logging
    setup_logging(level='DEBUG')
    test_domain = "example.com"
    test_output_dir = "test_output/example.com/footprint"
    import os
    os.makedirs(test_output_dir, exist_ok=True)
    # Crie um arquivo all_subdomains.txt de teste
    with open(f"{test_output_dir}/all_subdomains.txt", 'w') as f:
        f.write("www.example.com\n")
        f.write("mail.example.com\n")
    ip_asn_data = perform_ip_asn_mapping(test_domain, test_output_dir)
    if ip_asn_data:
        logger.debug(f"Dados de IP e ASN de {test_domain}: {ip_asn_data}")
    import shutil
    shutil.rmtree("test_output", ignore_errors=True)
