import logging
import subprocess
import json
import os
import time
import yaml  # Para lidar com a saída do nuclei (pode ser YAML ou JSON)
from Wappalyzer import Wappalyzer, WebPage  # Importar as classes do python-wappalyzer

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

def execute_command(command):
    """Executa um comando e retorna a saída, erro e código de retorno."""
    process = subprocess.run(command, capture_output=True, text=True, check=False)
    return process.stdout.strip(), process.stderr.strip(), process.returncode

def analyze_with_wappalyzer(html_content, url):
    """Analisa o conteúdo HTML usando python-wappalyzer."""
    try:
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_body(html_content, url)
        logger.debug(f"Resultado wappalyzer: {webpage}")
        return wappalyzer.analyze(webpage)
    except Exception as e:
        logger.error(f"Erro ao analisar com Wappalyzer: {e}")
        return None

def run_nuclei(domain, output_file, templates=None):
    """Executa a ferramenta nuclei para o domínio e salva a saída em JSON."""
    if not verify_tool_availability("nuclei"):
        return False

    command = ["nuclei", "-target", domain, "-j", "-o", output_file]
    if templates:
        command.extend(["-t", templates])

    stdout, stderr, returncode = execute_command(command)

    if returncode == 0:
        logger.info(f"Saída do nuclei salva em: {output_file}")
        #logger.debug(f"Stdout do nuclei: {stdout}")
        return True
    else:
        logger.error(f"Erro ao executar nuclei para {domain}: {stderr}")
        return False

def analyze_nuclei_output(output_file):
    """Analisa o arquivo JSON de saída do nuclei."""
    if not os.path.exists(output_file):
        logger.warning(f"Arquivo de saída do nuclei não encontrado: {output_file}")
        return None
    try:
        with open(output_file, 'r') as f:
            # Ler cada linha do arquivo e tentar fazer o parsing como JSON
            results = []
            for line in f:
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError as e:
                    logger.error(f"Erro ao decodificar linha JSON do nuclei em {output_file}: {e} - Linha: {line.strip()}")
            return results
    except Exception as e:
        logger.error(f"Erro ao ler o arquivo do nuclei: {e}")
        return None

if __name__ == '__main__':
    from core.logging_config import setup_logging
    setup_logging(level='DEBUG')
    test_domain = "example.com"
    test_output_dir = "test_output/example.com/fingerprint"
    os.makedirs(test_output_dir, exist_ok=True)
    nuclei_output_file = f"{test_output_dir}/nuclei_results.json"

    if verify_tool_availability("nuclei"):
        logger.info("Nuclei está disponível.")
        if run_nuclei(test_domain, nuclei_output_file) and os.path.exists(nuclei_output_file):
            results = analyze_nuclei_output(nuclei_output_file)
            logger.debug(f"Resultados do Nuclei: {results}")
            os.remove(nuclei_output_file)
        else:
            logger.warning("Falha ao executar ou analisar o Nuclei.")
    else:
        logger.warning("Nuclei não está disponível.")

    # Testando o Wappalyzer (requer uma requisição HTTP para obter o HTML)
    import httpx
    try:
        response = httpx.get(f"http://{test_domain}", timeout=5)
        response.raise_for_status()
        wappalyzer_results = analyze_with_wappalyzer(response.text, response.url)
        logger.debug(f"Resultados do Wappalyzer: {wappalyzer_results}")
    except httpx.RequestError as e:
        logger.error(f"Erro ao fazer a requisição para testar o Wappalyzer: {e}")
    except httpx.HTTPStatusError as e:
        logger.error(f"Erro de status HTTP ao testar o Wappalyzer: {e}")

    import shutil
    shutil.rmtree("test_output", ignore_errors=True)
