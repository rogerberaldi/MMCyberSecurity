#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import argparse
import logging
import glob
import re
import subprocess
from datetime import datetime
from collections import defaultdict

# Configuração básica de logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class UnifiedReportGenerator:
    def __init__(self, output_dir="output", report_dir="output/report"):
        self.output_dir = output_dir
        self.report_dir = report_dir
        self.xsl_path = "nmap-bootstrap.xsl"
        
        # Ensure report directory exists
        os.makedirs(self.report_dir, exist_ok=True)
        os.makedirs(f"{self.report_dir}/html", exist_ok=True)
        os.makedirs(f"{self.report_dir}/assets", exist_ok=True)
        
        # Copy logo if exists
        if os.path.exists("logo.png"):
            import shutil
            shutil.copy2("logo.png", f"{self.report_dir}/assets/logo.png")

    def execute_command(self, command):
        """Execute shell command and return stdout, stderr, returncode"""
        try:
            process = subprocess.run(command, capture_output=True, text=True, check=False)
            return process.stdout, process.stderr, process.returncode
        except Exception as e:
            logger.error(f"Error executing command {' '.join(command)}: {e}")
            return None, str(e), 1

    def generate_html_from_nmap_xml(self, xml_path):
        """Convert Nmap XML to HTML using xsltproc and save to report/html directory"""
        if not os.path.exists(self.xsl_path):
            logger.error(f"XSL stylesheet not found: {self.xsl_path}")
            return None
            
        html_filename = os.path.basename(xml_path).replace(".xml", ".html")
        html_output_path = os.path.join(self.report_dir, "html", html_filename)
        
        command = ["xsltproc", "-o", html_output_path, self.xsl_path, xml_path]
        logger.info(f"Generating HTML: {html_filename}")
        
        _, stderr, returncode = self.execute_command(command)

        if returncode == 0 and os.path.exists(html_output_path):
            logger.info(f"  -> Success: {html_filename}")
            return html_output_path
        else:
            logger.error(f"  -> Failed to generate HTML from {xml_path}. Error: {stderr}")
            return None

    def read_full_tree(self):
        """Read the full tree structure from report/full_tree.txt"""
        tree_file = os.path.join("report", "full_tree.txt")
        if not os.path.exists(tree_file):
            logger.warning(f"Tree file not found: {tree_file}")
            return []
        
        try:
            with open(tree_file, 'r') as f:
                return [line.strip() for line in f.readlines() if line.strip()]
        except Exception as e:
            logger.error(f"Error reading tree file: {e}")
            return []

    def parse_tree_structure(self):
        """Parse the tree structure and extract relevant information"""
        tree_lines = self.read_full_tree()
        
        data = {
            'domains': set(),
            'subdomains': set(),
            'ips': set(),
            'ports': set(),
            'nmap_xmls': [],
            'service_xmls': [],
            'nuclei_files': [],
            'whatweb_files': [],
            'web_scans': []
        }
        
        for line in tree_lines:
            # Extract file path from tree structure
            clean_path = re.sub(r'^[├└│\s\-]+', '', line)
            
            if not clean_path or clean_path.startswith('report/'):
                continue
                
            # Extract domains from path
            if '.com.br' in clean_path or '.com' in clean_path:
                domain_match = re.search(r'([a-zA-Z0-9.-]+\.(com\.br|com|net|org))', clean_path)
                if domain_match:
                    domain = domain_match.group(1)
                    if 'www.' in domain or 'monitoramento.' in domain:
                        data['subdomains'].add(domain)
                    else:
                        data['domains'].add(domain)
            
            # Extract IPs from path
            ip_matches = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', clean_path)
            for ip in ip_matches:
                data['ips'].add(ip)
            
            # Extract ports from filenames
            port_matches = re.findall(r'_(\d{1,5})\.', clean_path)
            for port in port_matches:
                if 1 <= int(port) <= 65535:
                    data['ports'].add(port)
            
            # Categorize files
            if clean_path.endswith('.xml'):
                if 'nmap' in clean_path:
                    data['nmap_xmls'].append(clean_path)
                elif 'service' in clean_path:
                    data['service_xmls'].append(clean_path)
            elif 'nuclei' in clean_path and clean_path.endswith('.json'):
                data['nuclei_files'].append(clean_path)
            elif 'whatweb' in clean_path and clean_path.endswith('.json'):
                data['whatweb_files'].append(clean_path)
            elif 'web_scans' in clean_path:
                data['web_scans'].append(clean_path)
        
        # Convert sets to sorted lists
        for key in ['domains', 'subdomains', 'ips', 'ports']:
            data[key] = sorted(list(data[key]))
        
        return data

    def generate_search_data(self, data):
        """Generate search data for the frontend"""
        search_items = []
        
        # Add domains
        for domain in data['domains']:
            search_items.append({
                'type': 'domain',
                'value': domain,
                'display': f"🌍 {domain}",
                'category': 'Domínios'
            })
        
        # Add subdomains
        for subdomain in data['subdomains']:
            search_items.append({
                'type': 'subdomain', 
                'value': subdomain,
                'display': f"📄 {subdomain}",
                'category': 'Subdomínios'
            })
        
        # Add IPs
        for ip in data['ips']:
            search_items.append({
                'type': 'ip',
                'value': ip,
                'display': f"🖥️ {ip}",
                'category': 'IPs'
            })
        
        # Add ports
        for port in data['ports']:
            search_items.append({
                'type': 'port',
                'value': port,
                'display': f"🔌 Porta {port}",
                'category': 'Portas'
            })
        
        return search_items

    def process_all_nmap_xmls(self, data):
        """Process all Nmap XML files to generate HTML reports"""
        html_reports = []
        
        for xml_path in data['nmap_xmls'] + data['service_xmls']:
            full_xml_path = os.path.join(self.output_dir, xml_path)
            if os.path.exists(full_xml_path):
                html_path = self.generate_html_from_nmap_xml(full_xml_path)
                if html_path:
                    html_reports.append({
                        'name': os.path.basename(html_path),
                        'path': f"html/{os.path.basename(html_path)}",
                        'xml_source': xml_path,
                        'type': 'nmap' if 'nmap' in xml_path else 'service'
                    })
        
        return html_reports

    def generate_master_index(self, data, html_reports):
        """Generate master index.html with header search"""
        search_data = self.generate_search_data(data)
        
        html_content = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MaltauroMartins - CyberSecurity Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        body {{ 
            margin: 0; 
            padding: 0; 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f8f9fa;
        }}
        
        .header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 15px 0;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            position: sticky;
            top: 0;
            z-index: 1000;
        }}
        
        .header-content {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }}
        
        .logo-section {{
            display: flex;
            align-items: center;
        }}
        
        .logo {{
            height: 50px;
            margin-right: 20px;
        }}
        
        .header-title {{
            font-size: 1.4rem;
            font-weight: 600;
            margin: 0;
        }}
        
        .search-section {{
            position: relative;
            width: 400px;
        }}
        
        .search-input {{
            width: 100%;
            padding: 12px 45px 12px 15px;
            border: none;
            border-radius: 25px;
            background: rgba(255,255,255,0.95);
            color: #333;
            font-size: 14px;
        }}
        
        .search-icon {{
            position: absolute;
            right: 15px;
            top: 50%;
            transform: translateY(-50%);
            color: #6c757d;
        }}
        
        .search-results {{
            position: absolute;
            top: 100%;
            left: 0;
            right: 0;
            background: white;
            border-radius: 8px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.15);
            max-height: 400px;
            overflow-y: auto;
            z-index: 1001;
            display: none;
        }}
        
        .search-result-item {{
            padding: 12px 15px;
            border-bottom: 1px solid #f0f0f0;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        
        .search-result-item:hover {{
            background-color: #f8f9fa;
        }}
        
        .search-result-item:last-child {{
            border-bottom: none;
        }}
        
        .search-category {{
            font-size: 0.8rem;
            color: #6c757d;
            background: #e9ecef;
            padding: 2px 8px;
            border-radius: 12px;
        }}
        
        .main-content {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 30px 20px;
        }}
        
        .welcome-section {{
            text-align: center;
            margin-bottom: 40px;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        
        .stat-card {{
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 2px 15px rgba(0,0,0,0.08);
            text-align: center;
            transition: transform 0.2s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-2px);
        }}
        
        .stat-number {{
            font-size: 2.5rem;
            font-weight: bold;
            color: #007bff;
            margin-bottom: 5px;
        }}
        
        .stat-label {{
            color: #6c757d;
            font-weight: 500;
        }}
        
        .reports-section {{
            margin-top: 40px;
        }}
        
        .section-title {{
            color: #495057;
            border-bottom: 2px solid #007bff;
            padding-bottom: 10px;
            margin-bottom: 25px;
        }}
        
        .reports-table {{
            background: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 2px 15px rgba(0,0,0,0.08);
        }}
        
        .table-controls {{
            padding: 20px;
            background: #f8f9fa;
            border-bottom: 1px solid #dee2e6;
            display: flex;
            justify-content: between;
            align-items: center;
            flex-wrap: wrap;
            gap: 15px;
        }}
        
        .pagination-controls {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .pagination-controls select {{
            padding: 5px 10px;
            border: 1px solid #ced4da;
            border-radius: 4px;
        }}
        
        .table-filter {{
            flex: 1;
            max-width: 300px;
        }}
        
        .table-filter input {{
            width: 100%;
            padding: 8px 12px;
            border: 1px solid #ced4da;
            border-radius: 4px;
        }}
        
        .footer {{
            background: #f8f9fa;
            padding: 30px 0;
            margin-top: 60px;
            border-top: 1px solid #dee2e6;
        }}
        
        .footer-content {{
            max-width: 1200px;
            margin: 0 auto;
            text-align: center;
            padding: 0 20px;
        }}
        
        .footer-text {{
            margin: 0;
            font-size: 12px;
            color: #777;
            line-height: 1.6;
        }}
        
        .footer-text a {{
            color: #555;
            text-decoration: none;
        }}
        
        .footer-text a:hover {{
            text-decoration: underline;
        }}
        
        .hidden {{
            display: none !important;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <div class="logo-section">
                <img src="assets/logo.png" alt="MaltauroMartins" class="logo" onerror="this.style.display='none'">
                <h1 class="header-title">Relatório de Segurança Cibernética - DirectCall</h1>
            </div>
            <div class="search-section">
                <input type="text" class="search-input" id="searchInput" placeholder="Buscar IPs, portas, domínios..." onkeyup="performSearch()" onfocus="showSearchResults()" onblur="hideSearchResults()">
                <i class="fas fa-search search-icon"></i>
                <div class="search-results" id="searchResults"></div>
            </div>
        </div>
    </div>

    <div class="main-content">
        <div class="welcome-section">
            <h2>Relatório de Segurança Cibernética</h2>
            <p class="lead">Análise completa de segurança para DirectCall</p>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{len(data['domains'])}</div>
                    <div class="stat-label">Domínios</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(data['subdomains'])}</div>
                    <div class="stat-label">Subdomínios</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(data['ips'])}</div>
                    <div class="stat-label">IPs Identificados</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(data['ports'])}</div>
                    <div class="stat-label">Portas Encontradas</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(html_reports)}</div>
                    <div class="stat-label">Relatórios Gerados</div>
                </div>
            </div>
        </div>

        <div class="reports-section">
            <h3 class="section-title">Relatórios Disponíveis</h3>
            
            <div class="reports-table">
                <div class="table-controls">
                    <div class="table-filter">
                        <input type="text" id="tableFilter" placeholder="Filtrar relatórios..." onkeyup="filterTable()">
                    </div>
                    <div class="pagination-controls">
                        <label>Mostrar:</label>
                        <select id="pageSize" onchange="changePageSize()">
                            <option value="10">10</option>
                            <option value="25" selected>25</option>
                            <option value="50">50</option>
                        </select>
                        <label>por página</label>
                    </div>
                </div>
                
                <div class="table-responsive">
                    <table class="table table-hover mb-0" id="reportsTable">
                        <thead class="table-light">
                            <tr>
                                <th>Relatório</th>
                                <th>Tipo</th>
                                <th>Origem</th>
                                <th>Ação</th>
                            </tr>
                        </thead>
                        <tbody id="reportsTableBody">
"""

        # Add table rows for each report
        for report in html_reports:
            html_content += f"""
                            <tr>
                                <td><strong>{report['name']}</strong></td>
                                <td><span class="badge bg-primary">{report['type'].upper()}</span></td>
                                <td><small class="text-muted">{report['xml_source']}</small></td>
                                <td>
                                    <a href="{report['path']}" target="_blank" class="btn btn-sm btn-outline-primary">
                                        <i class="fas fa-external-link-alt"></i> Visualizar
                                    </a>
                                </td>
                            </tr>
"""

        html_content += f"""
                        </tbody>
                    </table>
                </div>
                
                <div class="table-controls">
                    <div id="tableInfo" class="text-muted"></div>
                    <div id="tablePagination"></div>
                </div>
            </div>
        </div>
    </div>

    <footer class="footer">
        <div class="footer-content">
            <p class="footer-text">
                Documento confidencial - Este relatório foi gerado pela <a href="https://maltauromartins.com">MaltauroMartins</a> para Directcall.<br/>
                Relatório Técnico de Segurança Cibernética - Gerado em {datetime.now().strftime("%d/%m/%Y")}.<br/>
                <a href="https://maltauromartins.com" target="_blank">MaltauroMartins Soluções Tecnológicas</a>
            </p>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Search data
        const searchData = {json.dumps(search_data, ensure_ascii=False)};
        
        // Table pagination
        let currentPage = 1;
        let pageSize = 25;
        let filteredData = [];
        
        function performSearch() {{
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            const resultsContainer = document.getElementById('searchResults');
            
            if (searchTerm.length < 2) {{
                resultsContainer.style.display = 'none';
                return;
            }}
            
            const results = searchData.filter(item => 
                item.value.toLowerCase().includes(searchTerm) ||
                item.display.toLowerCase().includes(searchTerm)
            );
            
            resultsContainer.innerHTML = '';
            
            if (results.length === 0) {{
                resultsContainer.innerHTML = '<div class="search-result-item">Nenhum resultado encontrado</div>';
            }} else {{
                results.slice(0, 10).forEach(item => {{
                    const div = document.createElement('div');
                    div.className = 'search-result-item';
                    div.innerHTML = `
                        <span>${{item.display}}</span>
                        <span class="search-category">${{item.category}}</span>
                    `;
                    div.onclick = () => selectSearchResult(item);
                    resultsContainer.appendChild(div);
                }});
            }}
            
            resultsContainer.style.display = 'block';
        }}
        
        function showSearchResults() {{
            const searchTerm = document.getElementById('searchInput').value;
            if (searchTerm.length >= 2) {{
                document.getElementById('searchResults').style.display = 'block';
            }}
        }}
        
        function hideSearchResults() {{
            setTimeout(() => {{
                document.getElementById('searchResults').style.display = 'none';
            }}, 200);
        }}
        
        function selectSearchResult(item) {{
            document.getElementById('searchInput').value = item.value;
            document.getElementById('searchResults').style.display = 'none';
            
            // Filter table based on selection
            document.getElementById('tableFilter').value = item.value;
            filterTable();
        }}
        
        function filterTable() {{
            const filterValue = document.getElementById('tableFilter').value.toLowerCase();
            const table = document.getElementById('reportsTable');
            const rows = table.getElementsByTagName('tr');
            
            filteredData = [];
            
            for (let i = 1; i < rows.length; i++) {{
                const row = rows[i];
                const text = row.textContent.toLowerCase();
                
                if (text.includes(filterValue)) {{
                    filteredData.push(row);
                    row.style.display = '';
                }} else {{
                    row.style.display = 'none';
                }}
            }}
            
            updatePagination();
        }}
        
        function changePageSize() {{
            pageSize = parseInt(document.getElementById('pageSize').value);
            currentPage = 1;
            updatePagination();
        }}
        
        function updatePagination() {{
            const totalItems = filteredData.length || document.querySelectorAll('#reportsTable tbody tr:not([style*="display: none"])').length;
            const totalPages = Math.ceil(totalItems / pageSize);
            
            // Update info
            const start = (currentPage - 1) * pageSize + 1;
            const end = Math.min(currentPage * pageSize, totalItems);
            document.getElementById('tableInfo').textContent = `Mostrando ${{start}} a ${{end}} de ${{totalItems}} registros`;
            
            // Update pagination buttons
            const paginationContainer = document.getElementById('tablePagination');
            paginationContainer.innerHTML = '';
            
            if (totalPages > 1) {{
                const nav = document.createElement('nav');
                const ul = document.createElement('ul');
                ul.className = 'pagination pagination-sm mb-0';
                
                // Previous button
                const prevLi = document.createElement('li');
                prevLi.className = `page-item ${{currentPage === 1 ? 'disabled' : ''}}`;
                prevLi.innerHTML = '<a class="page-link" href="#" onclick="changePage(${{currentPage - 1}})">Anterior</a>';
                ul.appendChild(prevLi);
                
                // Page numbers
                for (let i = 1; i <= totalPages; i++) {{
                    if (i === 1 || i === totalPages || (i >= currentPage - 2 && i <= currentPage + 2)) {{
                        const li = document.createElement('li');
                        li.className = `page-item ${{i === currentPage ? 'active' : ''}}`;
                        li.innerHTML = `<a class="page-link" href="#" onclick="changePage(${{i}})">${{i}}</a>`;
                        ul.appendChild(li);
                    }} else if (i === currentPage - 3 || i === currentPage + 3) {{
                        const li = document.createElement('li');
                        li.className = 'page-item disabled';
                        li.innerHTML = '<span class="page-link">...</span>';
                        ul.appendChild(li);
                    }}
                }}
                
                // Next button
                const nextLi = document.createElement('li');
                nextLi.className = `page-item ${{currentPage === totalPages ? 'disabled' : ''}}`;
                nextLi.innerHTML = '<a class="page-link" href="#" onclick="changePage(${{currentPage + 1}})">Próximo</a>';
                ul.appendChild(nextLi);
                
                nav.appendChild(ul);
                paginationContainer.appendChild(nav);
            }}
        }}
        
        function changePage(page) {{
            const totalItems = filteredData.length || document.querySelectorAll('#reportsTable tbody tr:not([style*="display: none"])').length;
            const totalPages = Math.ceil(totalItems / pageSize);
            
            if (page >= 1 && page <= totalPages) {{
                currentPage = page;
                updatePagination();
            }}
        }}
        
        // Initialize
        document.addEventListener('DOMContentLoaded', function() {{
            filterTable();
        }});
    </script>
</body>
</html>"""

        index_path = os.path.join(self.report_dir, "index.html")
        with open(index_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"Master index generated: {index_path}")
        return index_path

    def generate_all_reports(self, target_filter=None):
        """Generate all reports"""
        logger.info("Starting unified report generation...")
        
        # Parse tree structure to get all data
        data = self.parse_tree_structure()
        
        if not data['nmap_xmls'] and not data['service_xmls']:
            logger.warning("No XML files found for report generation")
            return
        
        logger.info(f"Found {len(data['nmap_xmls'])} Nmap XMLs and {len(data['service_xmls'])} Service XMLs")
        
        # Process all Nmap XMLs to generate HTML reports
        html_reports = self.process_all_nmap_xmls(data)
        
        # Generate master index
        self.generate_master_index(data, html_reports)
        
        logger.info(f"Generated {len(html_reports)} HTML reports")
        logger.info(f"All reports available at: {self.report_dir}/index.html")

def main():
    parser = argparse.ArgumentParser(description="Unified MMCyberSec Report Generator")
    parser.add_argument("--output-dir", default="output", help="Output directory containing scan results")
    parser.add_argument("--report-dir", default="output/report", help="Report output directory")
    parser.add_argument("--target", help="Generate report for specific target only")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    generator = UnifiedReportGenerator(args.output_dir, args.report_dir)
    generator.generate_all_reports(args.target)

if __name__ == "__main__":
    main()