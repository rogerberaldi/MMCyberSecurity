import logging
import requests
import json
from core.utils import save_json, record_time
import socket
import time
import os

logger = logging.getLogger(__name__)

def geolocate_ip(ip_address):
    """Obtém informações de geolocalização para um endereço IP usando ip-api.com."""
    base_url = f"http://ip-api.com/json/{ip_address}"
    try:
        start_time = time.time()
        response = requests.get(base_url)
        response.raise_for_status()
        data = response.json()
        end_time = time.time()
        record_time(start_time, end_time, f"Geolocalização IP para {ip_address}")
        if data.get('status') == 'success':
            return data
        else:
            logger.warning(f"Falha na geolocalização para {ip_address}: {data.get('message')}")
            return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Erro ao geolocalizar IP {ip_address}: {e}")
        return None

def perform_geolocation(domain, output_dir):
    """Realiza a geolocalização dos IPs associados ao domínio."""
    logger.info(f"Iniciando geolocalização de IPs para: {domain}")
    geolocation_data = []
    ips = set()

#    try:
#        ip_address = socket.gethostbyname(domain)
#        ips.add(ip_address)
#    except socket.gaierror:
#        logger.warning(f"Não foi possível resolver o IP para o domínio: {domain}")
#
#    subdomains_file = f"{output_dir}/all_subdomains.txt"
#    if os.path.exists(subdomains_file):
#        with open(subdomains_file, 'r') as f:
#            for subdomain in f:
#                subdomain = subdomain.strip()
#                try:
#                    ip_address = socket.gethostbyname(subdomain)
#                    ips.add(ip_address)
#                except socket.gaierror:
#                    logger.debug(f"Não foi possível resolver o IP para o subdomínio: {subdomain}")
#
#    ip_asn_file = f"{output_dir}/ip_asn.json"
#    if os.path.exists(ip_asn_file):
#        try:
#            with open(ip_asn_file, 'r') as f:
#                ip_asn_data = json.load(f)
#                for item in ip_asn_data:
#                    if 'ip' in item:
#                        ips.add(item['ip'])
#        except json.JSONDecodeError:
#            logger.warning(f"Erro ao decodificar o arquivo JSON de IP/ASN: {ip_asn_file}")

    for ip in sorted(list(ips)):
        geo_info = geolocate_ip(ip)
        if geo_info:
            geolocation_data.append(geo_info)

    save_json(geolocation_data, f"{output_dir}/geolocation.json")
    logger.info(f"Geolocalização dos IPs para {domain} concluída. Resultados salvos em: {output_dir}/geolocation.json")
    return geolocation_data

if __name__ == '__main__':
    from core.logging_config import setup_logging
    setup_logging(level='DEBUG')
    test_domain = "example.com"
    test_output_dir = "test_output/example.com/footprint"
    import os
    os.makedirs(test_output_dir, exist_ok=True)
    # Crie um arquivo all_subdomains.txt de teste (opcional)
    with open(f"{test_output_dir}/all_subdomains.txt", 'w') as f:
        f.write("www.example.com\n")
    geolocation_data = perform_geolocation(test_domain, test_output_dir)
    if geolocation_data:
        logger.debug(f"Dados de geolocalização para {test_domain}: {geolocation_data}")
    import shutil
    shutil.rmtree("test_output", ignore_errors=True)
