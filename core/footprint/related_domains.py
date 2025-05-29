import logging
import json
import os
import time
from core.utils import save_text, record_time

logger = logging.getLogger(__name__)

def perform_related_domains(domain, output_dir):
    """Coleta domínios relacionados e alternate names (CNAME, SAN)."""
    start_time = time.time()
    logger.info(f"Iniciando coleta de domínios relacionados para: {domain}")
    related_domains = set()

    # Analisar registros CNAME do dns_enumeration.json
    dns_enumeration_file = f"{output_dir}/dns_enumeration.json"
    if os.path.exists(dns_enumeration_file):
        try:
            with open(dns_enumeration_file, 'r') as f:
                dns_data = json.load(f)
                if 'CNAME' in dns_data:
                    for cname in dns_data['CNAME']:
                        if '->' in cname:
                            alias, target = map(str.strip, cname.split('->', 1))
                            related_domains.add(alias)
                            related_domains.add(target)
                        else:
                            related_domains.add(cname)
        except json.JSONDecodeError:
            logger.warning(f"Erro ao decodificar o arquivo JSON de enumeração de DNS: {dns_enumeration_file}")

    # Analisar Subject Alternative Names (SANs) do dns_history.json (SecurityTrails)
    dns_history_file = f"{output_dir}/dns_history.json"
    if os.path.exists(dns_history_file):
        try:
            with open(dns_history_file, 'r') as f:
                history_data = json.load(f)
                if 'securitytrails' in history_data and 'ssl_info' in history_data['securitytrails'] and 'current' in history_data['securitytrails']['ssl_info'] and 'subject_alternative_names' in history_data['securitytrails']['ssl_info']['current']:
                    for san in history_data['securitytrails']['ssl_info']['current']['subject_alternative_names']:
                        related_domains.add(san)
        except json.JSONDecodeError:
            logger.warning(f"Erro ao decodificar o arquivo JSON de histórico de DNS: {dns_history_file}")

    # Adicionar o próprio domínio à lista de relacionados
    related_domains.add(domain)

    # Remover duplicatas e ordenar
    sorted_related_domains = sorted(list(related_domains))

    save_text("\n".join(sorted_related_domains), f"{output_dir}/related_domains.txt")
    end_time = time.time()
    record_time(start_time, end_time, f"Coleta de domínios relacionados para {domain}")
    logger.info(f"Domínios relacionados para {domain} coletados e salvos em: {output_dir}/related_domains.txt")
    return sorted_related_domains

if __name__ == '__main__':
    from core.logging_config import setup_logging
    setup_logging(level='DEBUG')
    test_domain = "example.com"
    test_output_dir = "test_output/example.com/footprint"
    import os
    os.makedirs(test_output_dir, exist_ok=True)
    # Crie arquivos de teste (simulando saídas de outros módulos)
    with open(f"{test_output_dir}/dns_enumeration.json", 'w') as f:
        json.dump({"CNAME": ["www.example.com -> example.com", "alias.com -> target.net"]}, f)
    with open(f"{test_output_dir}/dns_history.json", 'w') as f:
        json.dump({"securitytrails": {"ssl_info": {"current": {"subject_alternative_names": ["example.com", "san1.example.com"]}}}}, f)
    related = perform_related_domains(test_domain, test_output_dir)
    if related:
        logger.debug(f"Domínios relacionados para {test_domain}: {related}")
    import shutil
    shutil.rmtree("test_output", ignore_errors=True)
