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
from core.utils import save_json, record_time, execute_command, verify_tool_availability

logger = logging.getLogger(__name__)


def _is_web_service(service_info):
    """Verifica se um serviço é provavelmente um serviço web com base nas informações do Nmap."""
    name = service_info.get("name", "").lower()
    product = service_info.get("product", "").lower()
    port = service_info.get("port", "")
    
    # Check common web ports
    web_ports = ["80", "443", "8080", "8443", "8000", "8888", "9000", "3000"]
    if port in web_ports:
        return True
        
    # Check service names and products
    web_indicators = ["http", "https", "www", "ssl/http", "apache", "nginx", "iis"]
    return any(indicator in name or indicator in product for indicator in web_indicators)

def _make_url(host, port, service_name):
    """Cria uma URL com http ou https com base no nome do serviço Nmap."""
    scheme = "https" if ("ssl" in service_name.lower() or 
                        "https" in service_name.lower() or 
                        port == "443" or 
                        port == "8443") else "http"
    return f"{scheme}://{host}:{port}"

def analyze_http_headers(headers):
    """Analisa os cabeçalhos HTTP em busca de informações de tecnologias."""
    technologies = {}
    
    if not headers:
        return technologies
        
    server = headers.get('Server', headers.get('server'))
    if server:
        technologies['server'] = server
        server_lower = server.lower()
        if 'apache' in server_lower:
            technologies.setdefault('backend_language', []).append('PHP (possível)')
        elif 'nginx' in server_lower:
            technologies.setdefault('backend_language', []).append('PHP (possível)')
        elif 'node.js' in server_lower:
            technologies.setdefault('backend_language', []).append('Node.js')
        elif 'iis' in server_lower:
            technologies.setdefault('backend_language', []).append('ASP.NET (possível)')

    x_powered_by = headers.get('X-Powered-By', headers.get('x-powered-by'))
    if x_powered_by:
        technologies['x_powered_by'] = x_powered_by
        x_powered_lower = x_powered_by.lower()
        if 'php' in x_powered_lower:
            technologies.setdefault('backend_language', []).append('PHP')
        elif 'express' in x_powered_lower:
            technologies.setdefault('framework', []).append('Node.js Express framework')
        elif 'asp.net' in x_powered_lower:
            technologies.setdefault('framework', []).append('ASP.NET')

    set_cookie = headers.get('Set-Cookie', headers.get('set-cookie'))
    if set_cookie:
        if 'phpsessid' in set_cookie.lower():
            technologies.setdefault('backend_language', []).append('PHP (session cookie)')
        elif 'asp.net_sessionid' in set_cookie.lower():
            technologies.setdefault('backend_language', []).append('ASP.NET (session cookie)')

    content_security_policy = headers.get('Content-Security-Policy', headers.get('content-security-policy'))
    if content_security_policy:
        if 'unsafe-inline' in content_security_policy.lower() or 'unsafe-eval' in content_security_policy.lower():
            technologies.setdefault('javascript_security', []).append('CSP com diretivas inseguras (potencial)')

    return technologies

def analyze_html_content(soup, technologies):
    """Analisa o conteúdo HTML em busca de informações de tecnologias."""
    if not soup:
        return technologies
        
    # Buscar por comentários
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    for comment in comments:
        comment_lower = comment.lower()
        if 'wordpress' in comment_lower:
            technologies['cms'] = 'WordPress (possível)'
        elif 'joomla' in comment_lower:
            technologies['cms'] = 'Joomla (possível)'
        elif 'drupal' in comment_lower:
            technologies['cms'] = 'Drupal (possível)'

    # Buscar por padrões de URL e nomes de arquivos/diretórios
    links = soup.find_all('link', href=True)
    scripts = soup.find_all('script', src=True)
    for element in links + scripts:
        url = element.get('href') if element.name == 'link' else element.get('src')
        if not url:
            continue
            
        url_lower = url.lower()
        if '/wp-content/' in url_lower:
            technologies['cms'] = 'WordPress (provável)'
        elif '/modules/mod_' in url_lower:
            technologies['cms'] = 'Joomla (provável)'
        elif '/sites/default/files/' in url_lower:
            technologies['cms'] = 'Drupal (provável)'
        elif 'jquery' in url_lower:
            technologies.setdefault('javascript_library', []).append('jQuery')
        elif 'bootstrap' in url_lower:
            technologies.setdefault('css_framework', []).append('Bootstrap')
        elif 'react' in url_lower:
            technologies.setdefault('javascript_framework', []).append('React')
        elif 'angular' in url_lower:
            technologies.setdefault('javascript_framework', []).append('Angular')
        elif 'vue' in url_lower:
            technologies.setdefault('javascript_framework', []).append('Vue.js')

    # Buscar por classes e IDs com nomes comuns
    divs = soup.find_all('div')
    for div in divs:
        classes = div.get('class', [])
        if isinstance(classes, list) and any('wp-block-' in cls for cls in classes):
            technologies['cms'] = 'WordPress (provável - Gutenberg)'

    return technologies

def analyze_javascript(soup, technologies):
    """Analisa o código JavaScript em busca de informações de tecnologias."""
    if not soup:
        return technologies
        
    script_tags = soup.find_all('script')
    for script in script_tags:
        if script.string:
            script_content = script.string.lower()
            if 'express' in script_content:
                technologies.setdefault('framework', []).append('Node.js Express framework (JS)')
            if 'angular' in script_content:
                technologies.setdefault('javascript_framework', []).append('Angular (detected in JS)')
            if 'react' in script_content:
                technologies.setdefault('javascript_framework', []).append('React (detected in JS)')
    return technologies

def analyze_nmap_service_scan(xml_file):
    """Analisa o arquivo XML do Nmap service scan para identificar tecnologias e suas portas."""
    services = []
    if not os.path.exists(xml_file):
        logger.warning(f"Arquivo XML do Nmap não encontrado: {xml_file}")
        return services
        
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
                    cpe_elements = service.findall('cpe')

                    if name:
                        service_info['name'] = name
                        name_lower = name.lower()
                        if 'http' in name_lower:
                            service_info.setdefault('technology', []).append('HTTP')
                        if 'ssh' in name_lower:
                            service_info.setdefault('technology', []).append('SSH')
                        if 'ftp' in name_lower:
                            service_info.setdefault('technology', []).append('FTP')

                    if product:
                        service_info['product'] = product
                        product_lower = product.lower()
                        if 'node.js' in product_lower:
                            service_info.setdefault('technology', []).append('Node.js')
                        if 'express' in product_lower:
                            service_info.setdefault('technology', []).append('Node.js Express framework')
                        if 'apache httpd' in product_lower:
                            service_info.setdefault('technology', []).append('Apache httpd')
                        if 'nginx' in product_lower:
                            service_info.setdefault('technology', []).append('Nginx')
                        if 'rabbitmq' in product_lower:
                            service_info.setdefault('technology', []).append('RabbitMQ')
                        if 'mysql' in product_lower:
                            service_info.setdefault('technology', []).append('MySQL')
                        if 'cowboy httpd' in product_lower:
                            service_info.setdefault('technology', []).append('Cowboy httpd')
                        if 'microsoft iis' in product_lower:
                            service_info.setdefault('technology', []).append('Microsoft IIS')

                    if version:
                        service_info['version'] = version
                        if product:
                            product_lower = product.lower()
                            if 'openssh' in product_lower:
                                service_info['openssh_version'] = version
                            elif 'apache' in product_lower:
                                service_info['apache_version'] = version
                            elif 'nginx' in product_lower:
                                service_info['nginx_version'] = version

                    if extrainfo:
                        service_info['extrainfo'] = extrainfo
                        extrainfo_lower = extrainfo.lower()
                        if 'fedora' in extrainfo_lower:
                            service_info.setdefault('os', []).append('Fedora Linux (possível)')
                        elif 'ubuntu' in extrainfo_lower:
                            service_info.setdefault('os', []).append('Ubuntu Linux (possível)')
                        elif 'centos' in extrainfo_lower:
                            service_info.setdefault('os', []).append('CentOS Linux (possível)')

                    if cpe_elements:
                        service_info['cpe'] = [cpe.text for cpe in cpe_elements if cpe.text]
                        for cpe_text in service_info['cpe']:
                            if 'linux' in cpe_text.lower():
                                service_info.setdefault('os', []).append('Linux (possível)')
                            elif 'windows' in cpe_text.lower():
                                service_info.setdefault('os', []).append('Windows (possível)')

                    services.append(service_info)

    except ET.ParseError as e:
        logger.error(f"Erro ao analisar o arquivo XML do Nmap: {xml_file} - {e}")
    except Exception as e:
        logger.error(f"Erro inesperado ao processar XML do Nmap: {xml_file} - {e}")
        
    return services

def run_whatweb(target_url, output_json_file, aggression_level=3):
    """
    Executa o WhatWeb em uma URL específica com um nível de agressão.
    """
    if not verify_tool_availability("whatweb"):
        return None

    start_time = time.time()
    
    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_json_file), exist_ok=True)
    
    command = [
        "whatweb",
        f"--aggression={aggression_level}",
        "--log-json", output_json_file,
        "--max-threads", "4",
        "--read-timeout", "10",
        target_url
    ]

    logger.info(f"Executando WhatWeb em {target_url} com agressão nível {aggression_level}.")
    stdout, stderr, returncode = execute_command(command)
    end_time = time.time()
    record_time(start_time, end_time, f"WhatWeb em {target_url}")

    if returncode == 0 and os.path.exists(output_json_file) and os.path.getsize(output_json_file) > 0:
        logger.info("  -> WhatWeb executado com sucesso.")
        return output_json_file
    else:
        logger.error(f"  -> Falha ao executar WhatWeb em {target_url}. Erro: {stderr}")
        return None

def perform_http_analysis(target_url):
    """
    Realiza análise HTTP direta de uma URL para identificar tecnologias.
    """
    technologies = {}
    
    try:
        logger.info(f"Realizando análise HTTP direta para: {target_url}")
        
        # Try with different user agents to avoid blocking
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        with httpx.Client(timeout=15, follow_redirects=True, verify=False) as client:
            response = client.get(target_url, headers=headers)
            response.raise_for_status()
            
            # Analyze HTTP headers
            http_tech = analyze_http_headers(dict(response.headers))
            technologies.update(http_tech)
            
            # Analyze HTML content
            if response.text:
                soup = BeautifulSoup(response.text, 'html.parser')
                html_tech = analyze_html_content(soup, {})
                technologies.update(html_tech)
                
                # Analyze JavaScript
                js_tech = analyze_javascript(soup, {})
                technologies.update(js_tech)
                
                # Analyze with Wappalyzer if available
                try:
                    wappalyzer_results = analyze_with_wappalyzer(response.text, str(response.url))
                    if wappalyzer_results:
                        technologies['wappalyzer'] = list(wappalyzer_results)
                except Exception as e:
                    logger.debug(f"Wappalyzer analysis failed for {target_url}: {e}")
            
            technologies['response_status'] = response.status_code
            technologies['final_url'] = str(response.url)
            
    except httpx.TimeoutException:
        logger.warning(f"Timeout ao acessar {target_url}")
        technologies['error'] = 'timeout'
    except httpx.HTTPStatusError as e:
        logger.warning(f"Erro HTTP {e.response.status_code} ao acessar {target_url}")
        technologies['error'] = f'http_{e.response.status_code}'
    except httpx.RequestError as e:
        logger.warning(f"Erro de conexão ao acessar {target_url}: {e}")
        technologies['error'] = 'connection_error'
    except Exception as e:
        logger.error(f"Erro inesperado ao analisar {target_url}: {e}")
        technologies['error'] = 'unexpected_error'
    
    return technologies

def refactored_perform_web_tech_identification(
    service_scan_xml_map,
    base_ip_fingerprint_dir,
    original_target_context=""
):
    """
    Orquestra a identificação de tecnologias web e varredura de vulnerabilidades
    em serviços web identificados.
    """
    logger.info(f"Iniciando identificação de tecnologias web para o alvo: {original_target_context}")
    all_web_results = {}

    # Create output directory
    sanitized_hostname = original_target_context.replace('.', '_').replace(':', '_')
    web_scans_output_dir = os.path.join(base_ip_fingerprint_dir, "web_scans", sanitized_hostname)
    os.makedirs(web_scans_output_dir, exist_ok=True)

    if not service_scan_xml_map:
        logger.warning(f"Nenhum resultado de scan de serviço Nmap fornecido para {original_target_context}. Pulando identificação web.")
        return None

    for ip, nmap_xml_file in service_scan_xml_map.items():
        logger.info(f"Processando serviços para o IP: {ip}")
        all_web_results[ip] = {}
        
        # Parse Nmap service scan results
        services_on_ip = analyze_nmap_service_scan(nmap_xml_file)
        
        # Filter for web services
        web_services = [s for s in services_on_ip if _is_web_service(s)]

        if not web_services:
            logger.info(f"Nenhum serviço web identificado no IP {ip}.")
            continue
        
        logger.info(f"Serviços web identificados em {ip}: {[s.get('port') for s in web_services]}")

        for service in web_services:
            port = service.get("port")
            if not port:
                continue

            # Create URLs for connection and analysis
            target_url_for_connection = _make_url(ip, port, service.get("name", ""))
            target_host_for_analysis = _make_url(original_target_context, port, service.get("name", ""))

            logger.info(f"--- Analisando Host: {target_host_for_analysis} (Conectando a: {target_url_for_connection}) ---")

            url_results = {"nmap_info": service}

            # 1. Perform HTTP analysis
            http_analysis = perform_http_analysis(target_host_for_analysis)
            if http_analysis:
                url_results["http_analysis"] = http_analysis

            # 2. Execute WhatWeb
            whatweb_out_file = os.path.join(web_scans_output_dir, f"whatweb_{port}.json")
            if run_whatweb(target_host_for_analysis, whatweb_out_file, aggression_level=3):
                url_results["whatweb_file"] = whatweb_out_file

            # 3. Execute Nuclei - Technology Detection
            nuclei_tech_out = os.path.join(web_scans_output_dir, f"nuclei_tech_{port}.json")
            if run_nuclei(target_host_for_analysis, nuclei_tech_out, templates="technologies"):
                nuclei_tech_results = analyze_nuclei_output(nuclei_tech_out)
                if nuclei_tech_results:
                    url_results["nuclei_tech_results"] = nuclei_tech_results

            # 4. Execute Nuclei - Vulnerability Detection
            nuclei_vuln_out = os.path.join(web_scans_output_dir, f"nuclei_vulns_{port}.json")
            if run_nuclei(target_host_for_analysis, nuclei_vuln_out, 
                          templates="cves,vulnerabilities,misconfiguration,exposures",
                          severity_filter="medium,high,critical"):
                nuclei_vuln_results = analyze_nuclei_output(nuclei_vuln_out)
                if nuclei_vuln_results:
                    url_results["nuclei_vuln_results"] = nuclei_vuln_results

            all_web_results[ip][port] = url_results

    # Save consolidated results
    consolidated_web_results_file = os.path.join(web_scans_output_dir, "web_technologies_consolidated.json")
    save_json(all_web_results, consolidated_web_results_file)
    logger.info(f"Resultados consolidados da identificação web salvos em: {consolidated_web_results_file}")

    return consolidated_web_results_file

if __name__ == '__main__':
    from core.logging_config import setup_logging
    setup_logging(level='DEBUG')
    test_domain = "example.com"
    test_output_dir = "test_output/example.com/fingerprint"
    import os
    os.makedirs(test_output_dir, exist_ok=True)
    
    # Create test service scan XML
    nmap_output_content = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
    <host>
        <ports>
            <port protocol="tcp" portid="22">
                <service name="ssh" product="OpenSSH" version="7.6p1"/>
            </port>
            <port protocol="tcp" portid="80">
                <service name="http" product="Apache httpd" version="2.4.29"/>
            </port>
            <port protocol="tcp" portid="443">
                <service name="https" product="Apache httpd" version="2.4.29"/>
            </port>
            <port protocol="tcp" portid="3000">
                <service name="http" product="Node.js Express framework"/>
            </port>
        </ports>
    </host>
</nmaprun>"""
    
    with open(f"{test_output_dir}/service_scan.xml", 'w') as f:
        f.write(nmap_output_content)

    service_map = {"192.168.1.1": f"{test_output_dir}/service_scan.xml"}
    web_tech_results = refactored_perform_web_tech_identification(
        service_map, 
        test_output_dir, 
        original_target_context=test_domain
    )
    
    if web_tech_results:
        logger.debug(f"Tecnologias web para {test_domain}: {web_tech_results}")
    
    import shutil
    shutil.rmtree("test_output", ignore_errors=True)