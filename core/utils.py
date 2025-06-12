import subprocess
import json
import os
import time
import logging

logger = logging.getLogger(__name__)

def execute_command(command, output_file=None, error_file=None):
    """Executa um comando shell e retorna a saída, erro e código de retorno."""
    logger.debug(f"Executando comando: {' '.join(command)}")
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    stdout_decoded = stdout.decode('utf-8', errors='ignore').strip()
    stderr_decoded = stderr.decode('utf-8', errors='ignore').strip()
    return stdout_decoded, stderr_decoded, process.returncode

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


def save_json(data, filename):
    """Salva dados em formato JSON."""
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        logger.debug(f"Dados salvos em: {filename}")
    except Exception as e:
        logger.error(f"Erro ao salvar JSON em {filename}: {e}")

def save_text(data, filename):
    """Salva dados em formato de texto."""
    try:
        with open(filename, 'w') as f:
            f.write(data + '\n')
        logger.debug(f"Dados salvos em: {filename}")
    except Exception as e:
        logger.error(f"Erro ao salvar texto em {filename}: {e}")

def create_output_directory(base_dir, domain):
    """Cria o diretório de output para um domínio."""
    domain_dir = os.path.join(base_dir, domain)
    footprint_dir = os.path.join(domain_dir, 'footprint')
    fingerprint_dir = os.path.join(domain_dir, 'fingerprint')
    os.makedirs(footprint_dir, exist_ok=True)
    os.makedirs(fingerprint_dir, exist_ok=True)
    logger.debug(f"Diretórios de output criados para: {domain}")
    return domain_dir, footprint_dir, fingerprint_dir

def record_time(start_time, end_time, task_name):
    """Calcula e loga a duração de uma tarefa."""
    duration = end_time - start_time
    logger.info(f"Tempo de execução de '{task_name}': {duration:.2f} segundos")
    return duration

if __name__ == '__main__':
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

    # Teste da função execute_command
    stdout, stderr, returncode = execute_command(['ls', '-l'])
    logger.debug(f"Saída do comando: {stdout}")
    logger.debug(f"Erro do comando: {stderr}")
    logger.debug(f"Código de retorno: {returncode}")

    # Teste da função save_json
    test_data_json = {"chave": "valor"}
    save_json(test_data_json, 'temp_test.json')

    # Teste da função save_text
    test_data_text = "Linha de texto para teste."
    save_text(test_data_text, 'temp_test.txt')

    # Teste da função create_output_directory
    domain_dir, footprint_dir, fingerprint_dir = create_output_directory('test_output', 'example.com')
    logger.debug(f"Diretório de domínio: {domain_dir}")
    logger.debug(f"Diretório de footprint: {footprint_dir}")
    logger.debug(f"Diretório de fingerprint: {fingerprint_dir}")
    os.rmdir(footprint_dir)
    os.rmdir(fingerprint_dir)
    os.rmdir(domain_dir)
    os.remove('temp_test.json')
    os.remove('temp_test.txt')

    # Teste da função record_time
    start = time.time()
    time.sleep(1)
    end = time.time()
    record_time(start, end, 'Teste de tempo')
