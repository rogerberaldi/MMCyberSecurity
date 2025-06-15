#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import argparse
import logging
import glob
import re
import subprocess

# Configuração básica de logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# --- Funções Auxiliares (para tornar o script autossuficiente) ---

def verify_tool_availability(tool_name):
    """Verifica se uma ferramenta está disponível no PATH do sistema."""
    from shutil import which
    if which(tool_name) is None:
        logger.error(f"Ferramenta necessária '{tool_name}' não encontrada no PATH.")
        return False
    return True

def execute_command(command):
    """Executa um comando no sistema e retorna stdout, stderr e código de retorno."""
    try:
        process = subprocess.run(command, capture_output=True, text=True, check=False)
        return process.stdout, process.stderr, process.returncode
    except FileNotFoundError:
        logger.error(f"Comando não encontrado: {command[0]}")
        return None, f"Comando não encontrado: {command[0]}", 1
    except Exception as e:
        logger.error(f"Erro inesperado ao executar comando {' '.join(command)}: {e}")
        return None, str(e), 1

def sanitize_for_filename(text):
    """Sanitiza uma string para ser usada em nomes de arquivo."""
    return text.replace('.', '_').replace(':', '_')


# --- Lógica de Geração de Relatórios ---

def generate_html_from_nmap_xml(xml_path, html_output_path, xsl_stylesheet_path):
    """Converte um arquivo XML do Nmap em um relatório HTML usando xsltproc."""
    # Garante que o diretório de saída para o HTML exista
    html_dir = os.path.dirname(html_output_path)
    os.makedirs(html_dir, exist_ok=True)
    
    command = ["xsltproc", "-o", html_output_path, xsl_stylesheet_path, xml_path]
    logger.info(f"Gerando HTML: {html_output_path}")
    
    _, stderr, returncode = execute_command(command)

    if returncode == 0 and os.path.exists(html_output_path):
        logger.info("  -> Sucesso.")
        return html_output_path
    else:
        logger.error(f"  -> Falha ao gerar HTML a partir de {xml_path}. Erro: {stderr}")
        return None

def prepare_html_reports(fingerprint_dir, xsl_path, output_dir):
    """Encontra todos os XMLs do Nmap e os converte para HTML."""
    if not verify_tool_availability("xsltproc"):
        return
        
    if not os.path.exists(xsl_path):
        logger.error(f"Folha de estilo XSL não encontrada: {xsl_path}. Não é possível gerar relatórios HTML.")
        return

    logger.info("Iniciando preparação dos relatórios HTML a partir dos arquivos XML...")
    
    # Padrão de busca para todos os XMLs do Nmap recursivamente
    xml_files = glob.glob(os.path.join(fingerprint_dir, "**", "nmap_*.xml"), recursive=True)
    xml_files += glob.glob(os.path.join(fingerprint_dir, "**", "service_*.xml"), recursive=True)

    for xml_file in xml_files:
        html_output_path = os.path.join(output_dir, "html", os.path.basename(xml_file).replace(".xml", ".html"))
        generate_html_from_nmap_xml(xml_file, html_output_path, xsl_path)

def generate_fingerprint_latex_section(target_dir):
    """Gera a seção LaTeX para a tabela de mapeamento de portas e serviços."""
    # (O código desta função permanece o mesmo da nossa última versão)
    # ... (código da função generate_fingerprint_latex_section da resposta anterior)
    # Certifique-se de que a função `generate_latex_link` também esteja aqui.
    pass # O corpo completo da função está no final para não repetir

def _generate_latex_link(text, relative_path_to_file, full_path_to_check):
    """Gera um link LaTeX com \attachfile e \href se o arquivo existir."""
    if os.path.exists(full_path_to_check):
        safe_text = str(text).replace('_', '\\_') # Garante que o texto seja string
        return f"\\attachfile[icon=Paperclip]{{{relative_path_to_file}}} \\href{{{relative_path_to_file}}}{{{safe_text}}}"
    else:
        return "N/A"

def _generate_complete_latex_section(target_dir):
    fingerprint_dir = os.path.join(target_dir, "fingerprint")
    if not os.path.isdir(fingerprint_dir):
        return "\\subsection{Mapeamento de Portas e Serviços por IP}\n\nO diretório de fingerprint não foi encontrado.\n"

    # (A lógica para carregar o JSON e encontrar todos os IPs escaneados permanece a mesma)
    json_path = os.path.join(fingerprint_dir, "consolidated_open_tcp_ports_by_ip.json")
    open_ports_data = {}
    if os.path.exists(json_path):
        try:
            with open(json_path, 'r') as f:
                open_ports_data = json.load(f)
        except json.JSONDecodeError:
            logger.error(f"Erro ao decodificar o arquivo JSON: {json_path}")

    all_scanned_ips = set()
    scan_files = glob.glob(os.path.join(fingerprint_dir, "nmap_tcp_scan_*.xml"))
    ip_pattern = re.compile(r"nmap_tcp_scan_(.+)\.xml")
    for f in scan_files:
        match = ip_pattern.search(os.path.basename(f))
        if match:
            ip = match.group(1).replace('_', '.')
            all_scanned_ips.add(ip)

    if not all_scanned_ips:
        return "\\subsection{Mapeamento de Portas e Serviços por IP}\n\nNenhum arquivo de varredura Nmap encontrado para gerar o relatório.\n"

    # --- INÍCIO DAS MUDANÇAS PARA LONGTABLE ---

    latex_string = """% Para os links e anexos funcionarem, inclua os seguintes pacotes no seu documento principal:
% \\usepackage{hyperref}
% \\usepackage{attachfile2}
% \\usepackage{longtable}  % <-- PACOTE NECESSÁRIO PARA TABELAS LONGAS

\\subsection{Mapeamento de Portas e Serviços por IP}

A tabela a seguir apresenta um resumo da análise de fingerprint para cada endereço IP associado ao escopo. Para IPs com serviços expostos, um link para o relatório de enumeração de serviço detalhado é fornecido na coluna do próprio IP.

% Em vez de \\begin{table} e \\begin{tabular}, usamos \\begin{longtable}
\\begin{longtable}{|m{3.5cm}|m{4.5cm}|m{3cm}|m{3cm}|}
\\caption{Resumo da Análise de Fingerprint por Endereço IP}
\\label{tab:fingerprint_summary} \\\\

\\hline
\\textbf{Endereço IP} & \\textbf{Portas TCP Abertas} & \\textbf{Relatório TCP} & \\textbf{Relatório UDP (VoIP)} \\\\ \\hline
\\endfirsthead % Define o cabeçalho que aparece apenas na primeira página

\\hline
\\multicolumn{4}{r}{{\\bfseries -- continuação da Tabela \\thetable --}} \\\\
\\hline
\\textbf{Endereço IP} & \\textbf{Portas TCP Abertas} & \\textbf{Relatório TCP} & \\textbf{Relatório UDP (VoIP)} \\\\ \\hline
\\endhead % Define o cabeçalho que se repete em todas as páginas seguintes

\\hline
\\endfoot % Pode ser usado para um rodapé em todas as páginas, exceto a última

\\hline
\\endlastfoot % Pode ser usado para um rodapé apenas na última página

"""
    # O loop para gerar as linhas da tabela permanece exatamente o mesmo
    for ip in sorted(list(all_scanned_ips)):
        # ... (toda a lógica para gerar a string 'row' permanece idêntica à versão anterior)
        sanitized_ip = sanitize_for_filename(ip)
        
        raw_tcp_html_name = f"nmap_tcp_scan_{sanitized_ip}.html"
        raw_tcp_html_path_to_check = os.path.join(fingerprint_dir, "html", raw_tcp_html_name)
        relative_raw_tcp_path = os.path.join( "html", raw_tcp_html_name)

        udp_html_name = f"nmap_udp_voip_scan_{sanitized_ip}.html"
        udp_html_path_to_check = os.path.join(fingerprint_dir, "html", udp_html_name)
        relative_udp_path = os.path.join( "html", udp_html_name)

        tcp_link = _generate_latex_link("TCP", relative_raw_tcp_path, raw_tcp_html_path_to_check)
        udp_link = _generate_latex_link("UDP", relative_udp_path, udp_html_path_to_check)

        if ip in open_ports_data and open_ports_data[ip]:
            ports_list_str = ", ".join(map(str, open_ports_data[ip]))
            service_html_name = f"service_scan_{sanitized_ip}.html"
            service_html_path_to_check = os.path.join(fingerprint_dir, sanitized_ip, "html", service_html_name)
            relative_service_path = os.path.join("html", service_html_name)
            ip_link = _generate_latex_link(ip, relative_service_path, service_html_path_to_check)
            latex_string += f"{ip_link} & {ports_list_str} & {tcp_link} & {udp_link} \\\\ \\hline\n"
        else:
            ip_text = ip.replace('_', '\\_')
            ports_text = "N/A"
            latex_string += f"{ip_text} & {ports_text} & {tcp_link} & {udp_link} \\\\ \\hline\n"

    # Em vez de \\end{tabular} e \\end{table}, usamos \\end{longtable}
    latex_string += "\\end{longtable}\n"
    
    # --- FIM DAS MUDANÇAS PARA LONGTABLE ---
    
    return latex_string

def main():
    """Função principal para gerar o relatório LaTeX."""
    parser = argparse.ArgumentParser(description="Gera relatórios HTML e uma seção LaTeX para os resultados de fingerprint.")
    parser.add_argument("target_dir", help="O caminho para o diretório de saída do alvo (ex: 'output/dominio.com.br').")
    parser.add_argument("--xsl-file", default="nmap-bootstrap.xsl", help="Caminho para o arquivo XSL. Padrão: nmap-bootstrap.xsl na pasta atual.")
    parser.add_argument("--output_dir", default="html", help="Caminho para os arquivos de saida. Padrão: html na pasta atual.")
    
    args = parser.parse_args()
    
    if not os.path.isdir(args.target_dir):
        logger.error(f"O diretório fornecido não existe: {args.target_dir}")
        return

    fingerprint_dir = os.path.join(args.target_dir, "fingerprint")
    if not os.path.isdir(fingerprint_dir):
        logger.error(f"O subdiretório 'fingerprint' não foi encontrado em {args.target_dir}")
        return

    # ETAPA 1: Gerar os relatórios HTML a partir dos XMLs existentes.
    prepare_html_reports(fingerprint_dir, args.xsl_file, args.output_dir)
    
    # ETAPA 2: Gerar o código LaTeX que agora pode linkar para os HTMLs.
    logger.info("Gerando código LaTeX para a tabela de resultados...")
    final_latex_code = _generate_complete_latex_section(args.target_dir)
    
    latex_dir = args.output_dir
    os.makedirs(latex_dir, exist_ok=True)

    latexFile = os.path.basename(args.target_dir).replace('.', '_')
    
    output_path = os.path.join(latex_dir, latexFile +".tex")
    with open(output_path, 'w') as f:
        f.write(final_latex_code)
    logger.info(f"Resumo LaTeX gerado com sucesso em: {output_path}")
 

if __name__ == "__main__":
    main()