import logging
import httpx
import requests
from bs4 import BeautifulSoup, Comment
import json
import re
import os
import time
import xml.etree.ElementTree as ET
import subprocess
import tempfile

from core.fingerprint.advanced_web_scan import analyze_with_wappalyzer, run_nuclei, analyze_nuclei_output

from core.utils import save_json, record_time, execute_command

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

def analyze_http_headers(headers):
    """Analisa os cabeçalhos HTTP em busca de informações de tecnologias."""
    technologies = {}
    server = headers.get('Server')
    if server:
        technologies['server'] = server
        if 'apache' in server.lower():
            technologies.setdefault('backend_language', []).append('PHP (possível)')
        elif 'nginx' in server.lower():
            technologies.setdefault('backend_language', []).append('PHP (possível)')
        elif 'node.js' in server.lower():
            technologies.setdefault('backend_language', []).append('Node.js')

    x_powered_by = headers.get('X-Powered-By')
    if x_powered_by:
        technologies['x_powered_by'] = x_powered_by
        if 'php' in x_powered_by.lower():
            technologies.setdefault('backend_language', []).append('PHP')
        elif 'express' in x_powered_by.lower():
            technologies.setdefault('framework', []).append('Node.js Express framework')

    set_cookie = headers.get('Set-Cookie')
    if set_cookie:
        if 'phpsessid' in set_cookie.lower():
            technologies.setdefault('backend_language', []).append('PHP (session cookie)')

    content_security_policy = headers.get('Content-Security-Policy')
    if content_security_policy:
        if 'unsafe-inline' in content_security_policy.lower() or 'unsafe-eval' in content_security_policy.lower():
            technologies.setdefault('javascript_security', []).append('CSP com diretivas inseguras (potencial)')

    return technologies

def analyze_html_content(soup, technologies):
    """Analisa o conteúdo HTML em busca de informações de tecnologias."""
    # Buscar por comentários
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    for comment in comments:
        if 'wordpress' in comment.lower():
            technologies['cms'] = 'WordPress (possível)'
        elif 'joomla' in comment.lower():
            technologies['cms'] = 'Joomla (possível)'
        elif 'drupal' in comment.lower():
            technologies['cms'] = 'Drupal (possível)'

    # Buscar por padrões de URL e nomes de arquivos/diretórios
    links = soup.find_all('link', href=True)
    scripts = soup.find_all('script', src=True)
    for element in links + scripts:
        url = element['href'] if element.name == 'link' else element['src']
        if '/wp-content/' in url:
            technologies['cms'] = 'WordPress (provável)'
        elif '/modules/mod_' in url:
            technologies['cms'] = 'Joomla (provável)'
        elif '/sites/default/files/' in url:
            technologies['cms'] = 'Drupal (provável)'
        elif 'jquery' in url.lower():
            technologies.setdefault('javascript_library', []).append('jQuery')
        elif 'bootstrap' in url.lower():
            technologies.setdefault('css_framework', []).append('Bootstrap')
        elif 'react' in url.lower():
            technologies.setdefault('javascript_framework', []).append('React')
        elif 'angular' in url.lower():
            technologies.setdefault('javascript_framework', []).append('Angular')
        elif 'vue' in url.lower():
            technologies.setdefault('javascript_framework', []).append('Vue.js')

    # Buscar por classes e IDs com nomes comuns
    divs = soup.find_all('div')
    for div in divs:
        if 'wp-block-' in div.get('class', []):
            technologies['cms'] = 'WordPress (provável - Gutenberg)'

    return technologies

def analyze_javascript(soup, technologies):
    """Analisa o código JavaScript em busca de informações de tecnologias."""
    script_tags = soup.find_all('script')
    for script in script_tags:
        if script.string:
            if 'express' in script.string:
                technologies.setdefault('framework', []).append('Node.js Express framework (JS)')
            # Podemos adicionar mais padrões de análise de JavaScript aqui
    return technologies

def analyze_nmap_service_scan(xml_file):
    """Analisa o arquivo XML do Nmap service scan para identificar tecnologias e suas portas."""
    services = []
    if os.path.exists(xml_file):
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            for host in root.findall('host'):
                for port_element in host.findall('ports/port'):
                    port_id = port_element.get('portid')
                    protocol = port_element.get('protocol')
                    service = port_element.find('service')
                    if service is not None:
                        service_info = {"port": port_id, "protocol": protocol}
                        name = service.get('name')
                        product = service.get('product')
                        version = service.get('version')
                        extrainfo = service.get('extrainfo')
                        cpe = service.find('cpe')

                        if name:
                            service_info['name'] = name
                            if 'http' in name.lower():
                                service_info.setdefault('technology', []).append('HTTP')
                            if 'ssh' in name.lower():
                                service_info.setdefault('technology', []).append('SSH')
                            # Outros serviços comuns podem ser adicionados aqui

                        if product:
                            service_info['product'] = product
                            if 'node.js' in product.lower():
                                service_info.setdefault('technology', []).append('Node.js')
                            if 'express' in product.lower():
                                service_info.setdefault('technology', []).append('Node.js Express framework')
                            if 'apache httpd' in product.lower():
                                service_info.setdefault('technology', []).append('Apache httpd')
                            if 'nginx' in product.lower():
                                service_info.setdefault('technology', []).append('Nginx')
                            if 'rabbitmq' in product.lower():
                                service_info.setdefault('technology', []).append('RabbitMQ')
                            if 'mysql' in product.lower():
                                service_info.setdefault('technology', []).append('MySQL (possível)')
                            if 'cowboy httpd' in product.lower():
                                service_info.setdefault('technology', []).append('Cowboy httpd')

                        if version:
                            service_info['version'] = version
                            if product and 'openssh' in product.lower():
                                service_info['openssh_version'] = version
                            if product and 'apache' in product.lower():
                                service_info['apache_version'] = version

                        if extrainfo:
                            service_info['extrainfo'] = extrainfo
                            if product and 'apache' in product.lower() and 'fedora' in extrainfo.lower():
                                service_info.setdefault('os', []).append('Fedora Linux (possível)')

                        if cpe is not None:
                            service_info['cpe'] = cpe.text
                            if 'linux' in cpe.text.lower():
                                service_info.setdefault('os', []).append('Linux (possível)')

                        services.append(service_info)

        except ET.ParseError as e:
            logger.warning(f"Erro ao analisar o arquivo XML do Nmap: {xml_file} - {e}")
    return services

def run_whatweb(domain, log_file):
    """Executa a ferramenta whatweb para identificar tecnologias web e salva a saída em JSON."""
    if not verify_tool_availability("whatweb"):
        return False

    command = ["whatweb", "-v", "--log-json", log_file, domain]
    stdout, stderr, returncode = execute_command(command)

    # Salva o stdout em um arquivo .out
    output_file = f"{log_file}.out"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(stdout)

    if returncode == 0:
        logger.info(f"Saída do whatweb salva em: {log_file}")
        logger.info(f"Conteúdo do stdout salvo em: {output_file}")
        return True
    else:
        logger.error(f"Erro ao executar whatweb para {domain}: {stderr}")
        return False

def perform_web_tech_identification(domain, output_dir):
    """Identifica tecnologias web utilizadas no domínio."""
    start_time = time.time()
    logger.info(f"Iniciando identificação de tecnologias web para: {domain}")
    web_technologies = {"services": []}
    service_scan_xml = f"{output_dir}/service_scan.xml"
    whatweb_json_file = f"{output_dir}/whatweb_results.json"
    nuclei_json_file = f"{output_dir}/nuclei_results.json"
#    nuclei_tech_json_file = f"{output_dir}/nuclei_tech_results.json"
#    nuclei_cves_json_file = f"{output_dir}/nuclei_cves_results.json"
#    nuclei_vulns_json_file = f"{output_dir}/nuclei_vulns_results.json"
    html_content = None
    response_url = None

    try:
        url = f"http://{domain}" # Tentar com HTTP primeiro
        with httpx.Client() as client:
            response = client.get(url, follow_redirects=True, timeout=10)
            response.raise_for_status()
            html_content = response.text
            response_url = str(response.url)
            http_tech = analyze_http_headers(response.headers)
            html_tech = analyze_html_content(BeautifulSoup(response.text, 'html.parser'), {})
            js_tech = analyze_javascript(BeautifulSoup(response.text, 'html.parser'), {})
            web_technologies.update(http_tech)
            web_technologies.update(html_tech)
            web_technologies.update(js_tech)

            # Analisar com Wappalyzer
            wappalyzer_results = analyze_with_wappalyzer(response.text, str(response.url))
            if wappalyzer_results:
                web_technologies['wappalyzer'] = wappalyzer_results

    except httpx.RequestError as e:
        logger.warning(f"Erro ao acessar {domain}: {e}.")

    except httpx.HTTPStatusError as e:
        logger.warning(f"Erro de status HTTP ao acessar {domain}: {e}")

    except Exception as e:
        logger.error(f"Erro inesperado ao acessar {domain}: {e}")

    # Analisar com Wappalyzer (agora fora do bloco try da requisição principal)
    if html_content and response_url:
        wappalyzer_results = analyze_with_wappalyzer(html_content, response_url)
        if wappalyzer_results:
            web_technologies['wappalyzer'] = wappalyzer_results

    # Executar e analisar Nuclei
    nuclei_success = run_nuclei(domain, nuclei_json_file)
    if nuclei_success and os.path.exists(nuclei_json_file):
        nuclei_results = analyze_nuclei_output(nuclei_json_file)
        if nuclei_results:
            web_technologies['nuclei'] = nuclei_results
        os.remove(nuclei_json_file)

    # Executar e analisar Nuclei para tecnologias
 #   nuclei_success = run_nuclei(domain, nuclei_tech_json_file, templates="tech/")
 #   if nuclei_success and os.path.exists(nuclei_tech_json_file):
 #       nuclei_results = analyze_nuclei_output(nuclei_tech_json_file)
 #       if nuclei_results:
 #           web_technologies['nuclei_tech'] = nuclei_results
 #       os.remove(nuclei_tech_json_file)

    # Executar e analisar Nuclei para CVEs
#    nuclei_success = run_nuclei(domain, nuclei_cves_json_file, templates="cves/")
#    if nuclei_success and os.path.exists(nuclei_cves_json_file):
#        nuclei_results = analyze_nuclei_output(nuclei_cves_json_file)
#        if nuclei_results:
#            web_technologies['nuclei_cvs'] = nuclei_results
#        os.remove(nuclei_cves_json_file)

    # Executar e analisar Nuclei para para vulnerabilidades gerais
#    nuclei_success = run_nuclei(domain, nuclei_vulns_json_file, templates="vulns/")
#    if nuclei_success and os.path.exists(nuclei_vulns_json_file):
#        nuclei_results = analyze_nuclei_output(nuclei_vulns_json_file)
#        if nuclei_results:
#            web_technologies['nuclei_vulns'] = nuclei_results
#        os.remove(nuclei_vulns_json_file)

    # Executar WhatWeb (já integrado)
    if run_whatweb(domain, whatweb_json_file) and os.path.exists(whatweb_json_file):
        try:
            with open(whatweb_json_file, 'r') as f:
                whatweb_output_list = json.load(f)
                if whatweb_output_list and isinstance(whatweb_output_list, list) and len(whatweb_output_list) > 0:
                    whatweb_results = whatweb_output_list[0].get('plugins')
                    if whatweb_results:
                        web_technologies['whatweb'] = whatweb_results
        except json.JSONDecodeError as e:
            logger.error(f"Erro ao decodificar o JSON do whatweb de {whatweb_json_file}: {e}")
        finally:
            if os.path.exists(whatweb_json_file):
                os.remove(whatweb_json_file)

    # Adicionar resultados do Nmap (executado mesmo em caso de erro na requisição web)
    nmap_services = analyze_nmap_service_scan(service_scan_xml)
    web_technologies["services"].extend(nmap_services)

    save_json({"domain": domain, "web_technologies": web_technologies}, f"{output_dir}/web_tech.json")
    end_time = time.time()
    record_time(start_time, end_time, f"Identificação de tecnologias web para {domain}")
    logger.info(f"Tecnologias web identificadas para {domain} e salvas em: {output_dir}/web_tech.json")
    return web_technologies

if __name__ == '__main__':
    from core.logging_config import setup_logging
    setup_logging(level='DEBUG')
    test_domain = "example.com"
    test_output_dir = "test_output/example.com/fingerprint"
    import os
    os.makedirs(test_output_dir, exist_ok=True)
    # Crie um arquivo service_scan.xml de teste (simulando a saída do Nmap com a porta 15672)
    nmap_output_content = """
    <?xml version="1.0" encoding="UTF-8"?>
    <nmaprun>
        <host><ports>
            <port protocol="tcp" portid="22"><service name="ssh" product="OpenSSH" version="7.6p1"/></port>
            <port protocol="tcp" portid="80"><service name="http" product="Apache httpd" version="2.4.29"/></port>
            <port protocol="tcp" portid="15672"><service name="http" product="Cowboy httpd"/></port>
            <port protocol="tcp" portid="3000"><service name="http" product="Node.js Express framework"/></port>
            <port protocol="tcp" portid="5672"><service name="amqp" product="RabbitMQ"/></port>
        </ports></host>
    </nmaprun>
    """
    with open(f"{test_output_dir}/service_scan.xml", 'w') as f:
        f.write(nmap_output_content)

    web_tech_results = perform_web_tech_identification(test_domain, test_output_dir)
    if web_tech_results:
        logger.debug(f"Tecnologias web para {test_domain}: {web_tech_results}")
    import shutil
    shutil.rmtree("test_output", ignore_errors=True)

from bs4 import Comment
