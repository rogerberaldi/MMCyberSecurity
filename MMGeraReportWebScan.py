#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import argparse
import logging
import glob
import datetime 

from collections import defaultdict

# Configuração
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Funções de Parsing ---

def parse_nuclei_file(file_path):
    """Lê um arquivo JSON do Nuclei, que contém um JSON por linha."""
    findings = []
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        return findings
    try:
        with open(file_path, 'r') as f:
            for line in f:
                if line.strip():
                    findings.append(json.loads(line))
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Erro ao ler ou parsear o arquivo Nuclei {file_path}: {e}")
    return findings

def parse_whatweb_file(file_path):
    """Lê um arquivo JSON do WhatWeb."""
    if not os.path.exists(file_path) or os.path.getsize(file_path) < 5: # Ignora arquivos quase vazios
        return []
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Erro ao ler ou parsear o arquivo WhatWeb {file_path}: {e}")
    return []

def aggregate_scan_data(scan_dir):
    """Agrega todos os dados de scan de um diretório em um dicionário estruturado."""
    logger.info(f"Agregando dados do diretório: {scan_dir}")
    aggregated_data = defaultdict(lambda: {
        'whatweb': [],
        'nuclei_tech': [],
        'nuclei_vulns': []
    })
    
    # Encontra todos os arquivos e extrai a porta do nome
    for file_path in glob.glob(os.path.join(scan_dir, "*.json")):
        filename = os.path.basename(file_path)
        parts = filename.replace('.json', '').split('_')
        if len(parts) < 2 or not parts[-1].isdigit():
            continue
        
        port = parts[-1]
        
        if filename.startswith("whatweb"):
            aggregated_data[port]['whatweb'].extend(parse_whatweb_file(file_path))
        elif filename.startswith("nuclei_tech"):
            aggregated_data[port]['nuclei_tech'].extend(parse_nuclei_file(file_path))
        elif filename.startswith("nuclei_vulns"):
            aggregated_data[port]['nuclei_vulns'].extend(parse_nuclei_file(file_path))
            
    # Ordena por porta (como string)
    return dict(sorted(aggregated_data.items(), key=lambda item: int(item[0])))

# --- Funções de Geração de HTML ---

def get_severity_style(severity):
    """Retorna uma classe CSS e um ícone Font Awesome com base na severidade."""
    styles = {
        "critical": ("danger", "fa-exclamation-triangle"),
        "high": ("warning", "fa-fire"),
        "medium": ("info", "fa-info-circle"),
        "low": ("secondary", "fa-angle-double-right"),
        "info": ("success", "fa-check-circle"),
    }
    return styles.get(severity.lower(), ("secondary", "fa-question-circle"))

def get_severity_color(severity):
    """Retorna uma cor baseada na severidade da vulnerabilidade."""
    colors = {
        "critical": "#d9534f",
        "high": "#f0ad4e",
        "medium": "#5bc0de",
        "low": "#777",
        "info": "#5cb85c",
    }
    return colors.get(severity, "#777")

def _generate_html_head(subdomain):
    """Gera o cabeçalho <head> do HTML, incluindo CSS embutido para portabilidade."""
    # O CSS do Bootstrap v3.3.7 e do Font Awesome 4.7.0 são embutidos para garantir que o relatório
    # seja autocontido e funcione offline. O conteúdo real do CSS/JS é longo, então está omitido aqui,
    # mas o código completo no final terá tudo.
    return f"""
<head>
    <meta charset="UTF-8">
    <title>MaltauroMartins - CyberSecurity Report</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
    <style>
        body {{ padding-top: 50px; }}
        #sidebar {{ position: fixed; top: 51px; left: 0; bottom: 0; width: 250px; padding: 20px; background-color: #f5f5f5; border-right: 1px solid #eee; overflow-y: auto; }}
        #main-content {{ margin-left: 260px; }}
        .nav-sidebar > .active > a, .nav-sidebar > .active > a:hover, .nav-sidebar > .active > a:focus {{ color: #fff; background-color: #428bca; }}
        .port-section {{ padding-top: 60px; margin-top: -50px; }} /* Offset for navbar anchor */
        .vuln-details summary {{ font-size: 1.1em; font-weight: bold; cursor: pointer; }}
        .vuln-details pre {{ margin-top: 10px; }}
        .whatweb-table {{ margin-top: 15px; }}
    </style>
</head>
"""

def _generate_html_body(data, subdomain):
    """Gera o <body> completo do relatório, com sidebar e conteúdo principal."""
    # --- Sidebar (Índice de Navegação) ---
    sidebar_links = ""
    for port in data.keys():
        sidebar_links += f'<li><a href="#port_{port}">Porta {port}</a></li>'
    
    sidebar = f"""
    <div id="sidebar">
        <ul class="nav nav-sidebar">
            <li class="active"><a href="#">Visão Geral</a></li>
            {sidebar_links}
        </ul>
    </div>
    """

    # --- Conteúdo Principal ---
    main_content = ""
    for port, results in data.items():
        # TODO: Reconstruir a URL exata (http/https) a partir dos dados.
        url = f"http://{subdomain}:{port}"
        main_content += f'<div id="port_{port}" class="port-section"><h2>Porta {port} <small>({url})</small></h2>'

        
        
        # --- Seção Nuclei Tech ---
        if results['nuclei_tech']:
            main_content += "<h3><i class='fa fa-cogs'></i> Tecnologias (Nuclei)</h3><ul>"
            for tech in results['nuclei_tech']:
                main_content += f"<li><b>{tech.get('info', {}).get('name')}</b> <span class='text-muted'>({tech.get('template-id')})</span></li>"
            main_content += "</ul>"
            
        # --- Seção Nuclei Vulns ---
        if results['nuclei_vulns']:
            main_content += "<h3><i class='fa fa-exclamation-triangle'></i> Vulnerabilidades Encontradas (Nuclei)</h3>"
            sorted_vulns = sorted(results['nuclei_vulns'], key=lambda x: ['critical', 'high', 'medium', 'low', 'info'].index(x.get('info', {}).get('severity', 'info')))
            for vuln in sorted_vulns:
                info = vuln.get('info', {})
                severity = info.get('severity', 'info')
                sev_class, sev_icon = get_severity_style(severity)
                
                main_content += f"""
                <details class="vuln-details">
                    <summary class="text-{sev_class}">
                        <i class="fa {sev_icon}"></i> {info.get('name')} <span class="badge">{severity.upper()}</span>
                    </summary>
                    <div class="panel panel-default">
                        <div class="panel-body">
                            <p><strong>ID do Template:</strong> {vuln.get('template-id')}</p>
                            <p><strong>Tags:</strong> <span class="text-muted">{info.get('tags')}</span></p>
                            <p><strong>Descrição:</strong> {info.get('description')}</p>
                            <p><strong>Host Alvo:</strong> {vuln.get('host')}</p>
                            <strong>Detalhes Completos da Requisição/Resposta (JSON):</strong>
                            <pre>{json.dumps(vuln, indent=2, ensure_ascii=False)}</pre>
                        </div>
                    </div>
                </details>
                """
        # --- Seção WhatWeb ---
        if results['whatweb']:
            main_content += "<h3><i class='fa fa-info-circle'></i> Tecnologias (WhatWeb)</h3>"
            for whatweb_result in results['whatweb']:
                for plugin, details in whatweb_result.get("plugins", {}).items():
                    main_content += f"<h4>{plugin}</h4>"
                    main_content += '<table class="table table-bordered table-striped whatweb-table"><tbody>'
                    for key, value in details.items():
                        main_content += f"<tr><th style='width: 150px;'>{key.capitalize()}</th><td><pre style='margin:0;'>{json.dumps(value, indent=2)}</pre></td></tr>"
                    main_content += '</tbody></table>'

        main_content += "</div><hr>"
        footer_html = _generate_html_footer()
    body = f"""
<body>
    <nav class="navbar navbar-inverse navbar-fixed-top">
        <div class="container-fluid">
            <div class="navbar-header">
                <a class="navbar-brand" href="#">Relatório de Segurança Cibernética - DirectCall - Web scan {subdomain}</a>
            </div>
        </div>
    </nav>
    <div class="container-fluid">
        <div class="row">
            {sidebar}
            <div id="main-content" class="col-sm-9 col-sm-offset-3 col-md-10 col-md-offset-2">
                {main_content}
                {footer_html}
            </div>
        </div>
    </div>
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>
</body>
"""
    return body

def generate_html_report(data, output_dir, subdomain):
    """Função principal que monta e salva o relatório HTML."""
    logger.info(f"Gerando relatório HTML com layout avançado para {subdomain}...")


    html_head = _generate_html_head(subdomain)
    html_body = _generate_html_body(data, subdomain)
    
    full_html = f"<!DOCTYPE html>\n<html lang='pt-BR'>\n{html_head}\n{html_body}\n</html>"

    os.makedirs(f"{output_dir}/html", exist_ok=True)    
    output_path = os.path.join(output_dir, f"html/{subdomain.replace('.', '_')}.html")
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(full_html)
        
    logger.info(f"Relatório HTML detalhado gerado com sucesso em: {output_path}")
    return output_path

# --- Funções de Geração de LaTeX ---

def generate_latex_summary(data, output_dir, subdomain, html_report_path):
    """Gera uma tabela resumo em LaTeX."""
    
    latex = """
% Para os links e anexos funcionarem, inclua os seguintes pacotes no seu documento principal:
% \\usepackage{hyperref}
% \\usepackage{attachfile2}
% \\usepackage{longtable}

\\subsection{Resumo da Análise de Aplicações Web}
\\attachfile[icon=Paperclip]{"""+ html_report_path +"""}\\textbf{Relatório Detalhado}
\\begin{longtable}{|p{3cm}|p{6cm}|}
\\caption{Resumo da Análise Web para o Subdomínio """ + subdomain.replace('_', '\\_') + """}
\\label{tab:web_summary_""" + subdomain.replace('.', '_') + """} \\\\
\\hline
\\textbf{URL Alvo (Porta)} & \\textbf{Contagem de Vulnerabilidades} \\\\ \\hline
\\endfirsthead
% ... (cabeçalhos de continuação para longtable) ...
"""

    for port, results in data.items():
        url = f":{port}".replace('_', '\\_')
        
        vuln_counts = defaultdict(int)
        for vuln in results['nuclei_vulns']:
            severity = vuln.get('info', {}).get('severity', 'info')
            vuln_counts[severity] += 1
        
        counts_str = ", ".join([f"{k.capitalize()}: {v}" for k, v in sorted(vuln_counts.items())])
        if not counts_str:
            counts_str = "Nenhuma"
            
        #link_to_html = f"\\href{{{html_report_path}}}{{HTML Detalhado}}"
        #link_to_html = "HTML Detalhado"
        
        #latex += f"{url} & {counts_str} & {link_to_html} \\\\ \\hline\n"
        latex += f"{url} & {counts_str} \\\\ \\hline\n"
        
    latex += "\\end{longtable}\n"
    
    output_path = os.path.join(output_dir, f"{subdomain.replace('.', '_')}.tex")
    with open(output_path, 'w') as f:
        f.write(latex)
    logger.info(f"Resumo LaTeX gerado com sucesso em: {output_path}")
    return output_path

def _generate_html_footer():
    """Gera o código HTML para o rodapé padronizado com branding."""
    
    # Obtém o ano e a data atual para o relatório
    current_year = datetime.date.today().year
    # Configurando o locale para português para o nome do mês, se possível, ou usando uma formatação numérica
    # Para simplicidade e portabilidade, usaremos a data no formato DD/MM/AAAA
    current_date_str = datetime.date.today().strftime("%d/%m/%Y")

    footer_html = f"""
    <hr style="margin-top: 40px;">
    <footer class="footer" style="padding: 20px 0; margin-top: 20px;">
      <div class="container">
        
        
        <p class="text-muted" style="text-align: center; margin: 0; font-size: 12px; color: #777;">
          Documento confidencial - Este relatório foi gerado pela <a href="https://maltauromartins.com">MaltauroMartins</a> para Directcall. <br/>
          Relatório Técnico de Segurança Cibernética - Gerado em {current_date_str}.<br/>
          <a href="https://maltauromartins.com" target="_blank" style="color: #555; text-decoration: none;">MaltauroMartins Soluções Tecnológicas</a>
        </p>

      </div>
    </footer>
    """
    return footer_html

# --- Função Principal ---

def main():
    parser = argparse.ArgumentParser(description="Gera relatórios (HTML e LaTeX) para os resultados de uma varredura web.")
    parser.add_argument("web_scan_dir", help="O caminho para o diretório de resultados do web_scan de um subdomínio específico.")
    parser.add_argument("--output_dir", default="html", help="Caminho para os arquivos de saida. Padrão: html na pasta atual.")

    args = parser.parse_args()
    
    if not os.path.isdir(args.web_scan_dir):
        logger.error(f"O diretório fornecido não existe: {args.web_scan_dir}")
        return
        
    # Extrai o nome do subdomínio do caminho para usar no título
    subdomain_name = os.path.basename(args.web_scan_dir).replace('_', '.')

    # 1. Agregar todos os dados dos arquivos JSON
    scan_data = aggregate_scan_data(args.web_scan_dir)
    
    if not scan_data:
        logger.warning("Nenhum dado de scan encontrado no diretório. Nenhum relatório será gerado.")
        return

    # 2. Gerar o relatório HTML detalhado
    html_report_path = generate_html_report(scan_data, args.output_dir, subdomain_name)

    # 3. Gerar o resumo em LaTeX
    generate_latex_summary(scan_data, args.output_dir, subdomain_name, html_report_path)

if __name__ == "__main__":
    main()
