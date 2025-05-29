import logging
import requests
import json
from core.utils import save_json, record_time
import os
import time

logger = logging.getLogger(__name__)
SECURITYTRAILS_API_KEY = os.environ.get("SECURITYTRAILS_API_KEY") # Configure como variável de ambiente

def fetch_securitytrails_data(endpoint, extraHeaders=None):
    """Faz uma requisição para a API da SecurityTrails."""
    if not SECURITYTRAILS_API_KEY:
        logger.error("Chave da API da SecurityTrails não configurada. Defina a variável de ambiente SECURITYTRAILS_API_KEY.")
        return None

    base_url = f"https://api.securitytrails.com/v1/{endpoint}"
    headers = {"APIKEY": SECURITYTRAILS_API_KEY}
    if extraHeaders:
        headers.update(extraHeaders)

    try:
        start_time = time.time()
        response = requests.get(base_url, headers=headers)
        response.raise_for_status()
        data = response.json()
        end_time = time.time()
        record_time(start_time, end_time, f"SecurityTrails - {endpoint}")
        return data
    except requests.exceptions.RequestException as e:
        logger.warning(f"Erro ao consultar SecurityTrails ({endpoint}): {e}")
        return None

def perform_dns_history(domain, output_dir):
    """Realiza a coleta de informações de DNS, WHOIS e SSL via SecurityTrails."""
    logger.info(f"Iniciando coleta de informações da SecurityTrails para: {domain}")
    securitytrails_data = {"domain": domain, "securitytrails": {}}

    # Obter informações do domínio
    domain_info = fetch_securitytrails_data(f"domain/{domain}")
    if domain_info:
        securitytrails_data["securitytrails"]["domain_info"] = domain_info

#    # Obter informações de WHOIS
#    whois_info = fetch_securitytrails_data(f"domain/{domain}/whois")
#    if whois_info:
#        securitytrails_data["securitytrails"]["whois_info"] = whois_info

    # Obter informações de SSL
#    ssl_info = fetch_securitytrails_data(f"domain/{domain}/ssl")

#    if ssl_info and 'current' in ssl_info:
#        securitytrails_data["securitytrails"]["ssl_info"] = {"current": ssl_info['current']}
        # Podemos adicionar lógica para histórico de SSL se o plano gratuito permitir

    save_json(securitytrails_data, f"{output_dir}/dns_history.json")
    logger.info(f"Informações da SecurityTrails para {domain} salvas em: {output_dir}/dns_history.json")
    return securitytrails_data

if __name__ == '__main__':
    from core.logging_config import setup_logging
    setup_logging(level='DEBUG')
    test_domain = "example.com"
    test_output_dir = "test_output/example.com/footprint"
    import os
    os.makedirs(test_output_dir, exist_ok=True)
    # É necessário configurar a variável de ambiente SECURITYTRAILS_API_KEY para testar
    # Ex: export SECURITYTRAILS_API_KEY="sua_api_key"
    history_data = perform_dns_history(test_domain, test_output_dir)
    if history_data:
        logger.debug(f"Dados da SecurityTrails para {test_domain}: {history_data}")
    import shutil
    shutil.rmtree("test_output", ignore_errors=True)
