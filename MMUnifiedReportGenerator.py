#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import argparse
import logging
import glob
import re
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from collections import defaultdict
import ipaddress

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

    def generate_html_from_nmap_xml(self, xml_path, target_name):
        """Convert Nmap XML to HTML using xsltproc and save to report directory"""
        if not os.path.exists(self.xsl_path):
            logger.error(f"XSL stylesheet not found: {self.xsl_path}")
            return None
            
        # Create target-specific directory in report
        target_report_dir = os.path.join(self.report_dir, target_name.replace('.', '_'))
        os.makedirs(target_report_dir, exist_ok=True)
        
        html_filename = os.path.basename(xml_path).replace(".xml", ".html")
        html_output_path = os.path.join(target_report_dir, html_filename)
        
        command = ["xsltproc", "-o", html_output_path, self.xsl_path, xml_path]
        logger.info(f"Generating HTML: {html_output_path}")
        
        _, stderr, returncode = self.execute_command(command)

        if returncode == 0 and os.path.exists(html_output_path):
            logger.info(f"  -> Success: {html_filename}")
            return html_output_path
        else:
            logger.error(f"  -> Failed to generate HTML from {xml_path}. Error: {stderr}")
            return None

    def categorize_ip(self, ip_str):
        """Categorize IP into network segments"""
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_private:
                # For private IPs, group by /24 network
                network = ipaddress.ip_network(f"{ip_str}/24", strict=False)
                return f"Private-{network.network_address}"
            else:
                # For public IPs, group by /24 network
                network = ipaddress.ip_network(f"{ip_str}/24", strict=False)
                return f"Public-{network.network_address}"
        except:
            return f"Unknown-{ip_str}"

    def discover_targets(self):
        """Discover all targets from output directory"""
        targets = {}
        
        # Scan output directory for target directories
        for item in os.listdir(self.output_dir):
            target_path = os.path.join(self.output_dir, item)
            if os.path.isdir(target_path) and item != "report":
                targets[item] = {
                    'type': 'domain' if '.' in item else 'ip',
                    'path': target_path,
                    'fingerprint': os.path.join(target_path, 'fingerprint'),
                    'footprint': os.path.join(target_path, 'footprint'),
                    'ips': [],
                    'subdomains': [],
                    'reports': []
                }
                
                # Discover IPs associated with this target
                fingerprint_path = targets[item]['fingerprint']
                if os.path.exists(fingerprint_path):
                    # Look for IP-specific directories
                    for ip_item in os.listdir(fingerprint_path):
                        ip_path = os.path.join(fingerprint_path, ip_item)
                        if os.path.isdir(ip_path) and self.is_ip(ip_item.replace('_', '.')):
                            targets[item]['ips'].append(ip_item.replace('_', '.'))
                
                # Discover subdomains from web scans
                web_scans_path = os.path.join(fingerprint_path, 'web_scans')
                if os.path.exists(web_scans_path):
                    for subdomain_item in os.listdir(web_scans_path):
                        subdomain_path = os.path.join(web_scans_path, subdomain_item)
                        if os.path.isdir(subdomain_path):
                            subdomain = subdomain_item.replace('_', '.')
                            if subdomain not in targets[item]['subdomains']:
                                targets[item]['subdomains'].append(subdomain)

        return targets

    def is_ip(self, text):
        """Check if text is a valid IP address"""
        try:
            ipaddress.ip_address(text)
            return True
        except:
            return False

    def parse_nuclei_file(self, file_path):
        """Parse Nuclei JSON output file"""
        findings = []
        if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
            return findings
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    if line.strip():
                        finding = json.loads(line)
                        findings.append(finding)
        except Exception as e:
            logger.error(f"Error parsing Nuclei file {file_path}: {e}")
        return findings

    def parse_whatweb_file(self, file_path):
        """Parse WhatWeb JSON output file"""
        if not os.path.exists(file_path) or os.path.getsize(file_path) < 5:
            return []
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error parsing WhatWeb file {file_path}: {e}")
        return []

    def get_severity_color(self, severity):
        """Get color for vulnerability severity"""
        colors = {
            "critical": "#dc3545",
            "high": "#fd7e14", 
            "medium": "#ffc107",
            "low": "#28a745",
            "info": "#17a2b8"
        }
        return colors.get(severity.lower(), "#6c757d")

    def generate_navigation_tree(self, targets):
        """Generate hierarchical navigation tree"""
        # Organize IPs by network segments
        ip_tree = defaultdict(list)
        domain_tree = defaultdict(list)
        
        for target_name, target_data in targets.items():
            if target_data['type'] == 'ip':
                category = self.categorize_ip(target_name)
                ip_tree[category].append(target_name)
            else:
                # It's a domain
                domain_tree[target_name] = target_data['subdomains']
                
                # Also categorize associated IPs
                for ip in target_data['ips']:
                    category = self.categorize_ip(ip)
                    if ip not in ip_tree[category]:
                        ip_tree[category].append(ip)

        return ip_tree, domain_tree

    def generate_master_index(self, targets):
        """Generate master index.html with frame navigation"""
        ip_tree, domain_tree = self.generate_navigation_tree(targets)
        
        # Generate navigation HTML
        nav_html = ""
        
        # IP Section
        nav_html += '<div class="nav-section">'
        nav_html += '<h6 class="nav-header" onclick="toggleSection(\'ip-section\')">📍 IPs <span class="toggle-icon">▼</span></h6>'
        nav_html += '<div id="ip-section" class="nav-content">'
        
        for network, ips in sorted(ip_tree.items()):
            network_id = network.replace('.', '_').replace('-', '_')
            nav_html += f'<div class="nav-subsection">'
            nav_html += f'<div class="nav-subheader" onclick="toggleSubsection(\'{network_id}\')">🌐 {network} <span class="toggle-icon">▼</span></div>'
            nav_html += f'<div id="{network_id}" class="nav-subcontent">'
            
            for ip in sorted(ips):
                ip_safe = ip.replace('.', '_')
                nav_html += f'<div class="nav-item" onclick="loadReport(\'{ip_safe}\', \'ip\')" data-search="{ip}">'
                nav_html += f'<span class="nav-icon">🖥️</span> {ip}</div>'
            
            nav_html += '</div></div>'
        
        nav_html += '</div></div>'
        
        # Domains Section
        nav_html += '<div class="nav-section">'
        nav_html += '<h6 class="nav-header" onclick="toggleSection(\'domain-section\')">🌍 Domains <span class="toggle-icon">▼</span></h6>'
        nav_html += '<div id="domain-section" class="nav-content">'
        
        for domain, subdomains in sorted(domain_tree.items()):
            domain_safe = domain.replace('.', '_')
            nav_html += f'<div class="nav-subsection">'
            nav_html += f'<div class="nav-subheader" onclick="toggleSubsection(\'{domain_safe}\')">🏠 {domain} <span class="toggle-icon">▼</span></div>'
            nav_html += f'<div id="{domain_safe}" class="nav-subcontent">'
            
            # Main domain
            nav_html += f'<div class="nav-item" onclick="loadReport(\'{domain_safe}\', \'domain\')" data-search="{domain}">'
            nav_html += f'<span class="nav-icon">🌐</span> {domain}</div>'
            
            # Subdomains
            for subdomain in sorted(subdomains):
                subdomain_safe = subdomain.replace('.', '_')
                nav_html += f'<div class="nav-item subdomain" onclick="loadReport(\'{subdomain_safe}\', \'subdomain\')" data-search="{subdomain}">'
                nav_html += f'<span class="nav-icon">📄</span> {subdomain}</div>'
            
            nav_html += '</div></div>'
        
        nav_html += '</div></div>'

        html_content = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MaltauroMartins - CyberSecurity Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {{ margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }}
        
        .header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 15px 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            z-index: 1000;
            height: 80px;
        }}
        
        .header-content {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            height: 100%;
        }}
        
        .logo {{
            height: 50px;
            margin-right: 20px;
        }}
        
        .header-title {{
            font-size: 1.5rem;
            font-weight: 600;
            margin: 0;
        }}
        
        .search-container {{
            position: relative;
            width: 300px;
        }}
        
        .search-input {{
            width: 100%;
            padding: 8px 15px;
            border: none;
            border-radius: 25px;
            background: rgba(255,255,255,0.9);
            color: #333;
        }}
        
        .sidebar {{
            position: fixed;
            top: 80px;
            left: 0;
            width: 350px;
            height: calc(100vh - 80px);
            background: #f8f9fa;
            border-right: 1px solid #dee2e6;
            overflow-y: auto;
            padding: 20px 0;
            z-index: 999;
        }}
        
        .main-content {{
            margin-left: 350px;
            margin-top: 80px;
            padding: 20px;
            min-height: calc(100vh - 80px);
        }}
        
        .nav-section {{
            margin-bottom: 15px;
        }}
        
        .nav-header {{
            background: #e9ecef;
            padding: 12px 20px;
            margin: 0;
            cursor: pointer;
            font-weight: 600;
            color: #495057;
            border-left: 4px solid #007bff;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .nav-header:hover {{
            background: #dee2e6;
        }}
        
        .nav-content {{
            background: white;
        }}
        
        .nav-subsection {{
            border-left: 2px solid #e9ecef;
            margin-left: 20px;
        }}
        
        .nav-subheader {{
            padding: 10px 15px;
            background: #f8f9fa;
            cursor: pointer;
            font-weight: 500;
            color: #6c757d;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .nav-subheader:hover {{
            background: #e9ecef;
        }}
        
        .nav-subcontent {{
            background: white;
        }}
        
        .nav-item {{
            padding: 8px 20px;
            cursor: pointer;
            color: #495057;
            border-bottom: 1px solid #f8f9fa;
            display: flex;
            align-items: center;
        }}
        
        .nav-item:hover {{
            background: #e3f2fd;
            color: #1976d2;
        }}
        
        .nav-item.active {{
            background: #2196f3;
            color: white;
        }}
        
        .nav-item.subdomain {{
            margin-left: 20px;
            font-size: 0.9rem;
        }}
        
        .nav-icon {{
            margin-right: 8px;
            font-size: 0.9rem;
        }}
        
        .toggle-icon {{
            font-size: 0.8rem;
            transition: transform 0.3s;
        }}
        
        .toggle-icon.rotated {{
            transform: rotate(-90deg);
        }}
        
        .hidden {{
            display: none !important;
        }}
        
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            margin-top: 40px;
            border-top: 1px solid #dee2e6;
            text-align: center;
        }}
        
        .welcome-content {{
            text-align: center;
            padding: 60px 20px;
            color: #6c757d;
        }}
        
        .welcome-content h2 {{
            color: #495057;
            margin-bottom: 20px;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 40px;
        }}
        
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }}
        
        .stat-number {{
            font-size: 2rem;
            font-weight: bold;
            color: #007bff;
        }}
        
        .stat-label {{
            color: #6c757d;
            margin-top: 5px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <div style="display: flex; align-items: center;">
                <img src="assets/logo.png" alt="MaltauroMartins" class="logo" onerror="this.style.display='none'">
                <h1 class="header-title">Relatório de Segurança Cibernética - DirectCall</h1>
            </div>
            <div class="search-container">
                <input type="text" class="search-input" id="searchInput" placeholder="🔍 Buscar IPs, portas, domínios..." onkeyup="performSearch()">
            </div>
        </div>
    </div>

    <div class="sidebar">
        {nav_html}
    </div>

    <div class="main-content">
        <div id="reportContent" class="welcome-content">
            <h2>Bem-vindo ao Relatório de Segurança Cibernética</h2>
            <p>Selecione um item na navegação lateral para visualizar os resultados detalhados.</p>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{len([t for t in targets.values() if t['type'] == 'domain'])}</div>
                    <div class="stat-label">Domínios Analisados</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{sum(len(t['ips']) for t in targets.values())}</div>
                    <div class="stat-label">IPs Identificados</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{sum(len(t['subdomains']) for t in targets.values())}</div>
                    <div class="stat-label">Subdomínios Encontrados</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(targets)}</div>
                    <div class="stat-label">Alvos Totais</div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function toggleSection(sectionId) {{
            const content = document.getElementById(sectionId);
            const header = content.previousElementSibling;
            const icon = header.querySelector('.toggle-icon');
            
            if (content.style.display === 'none' || content.style.display === '') {{
                content.style.display = 'block';
                icon.classList.remove('rotated');
            }} else {{
                content.style.display = 'none';
                icon.classList.add('rotated');
            }}
        }}
        
        function toggleSubsection(subsectionId) {{
            const content = document.getElementById(subsectionId);
            const header = content.previousElementSibling;
            const icon = header.querySelector('.toggle-icon');
            
            if (content.style.display === 'none' || content.style.display === '') {{
                content.style.display = 'block';
                icon.classList.remove('rotated');
            }} else {{
                content.style.display = 'none';
                icon.classList.add('rotated');
            }}
        }}
        
        function loadReport(targetId, type) {{
            // Remove active class from all items
            document.querySelectorAll('.nav-item').forEach(item => {{
                item.classList.remove('active');
            }});
            
            // Add active class to clicked item
            event.target.closest('.nav-item').classList.add('active');
            
            // Load report content
            const reportContent = document.getElementById('reportContent');
            reportContent.innerHTML = '<div class="text-center"><div class="spinner-border" role="status"></div><p>Carregando relatório...</p></div>';
            
            // Try to load the specific report
            const reportPath = targetId + '/index.html';
            
            fetch(reportPath)
                .then(response => {{
                    if (response.ok) {{
                        return response.text();
                    }}
                    throw new Error('Report not found');
                }})
                .then(html => {{
                    reportContent.innerHTML = html;
                }})
                .catch(error => {{
                    reportContent.innerHTML = `
                        <div class="alert alert-warning">
                            <h4>Relatório não encontrado</h4>
                            <p>O relatório para <strong>${{targetId.replace('_', '.')}}</strong> ainda não foi gerado ou não está disponível.</p>
                            <p>Verifique se os scans foram executados corretamente para este alvo.</p>
                        </div>
                    `;
                }});
        }}
        
        function performSearch() {{
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            const navItems = document.querySelectorAll('.nav-item');
            const sections = document.querySelectorAll('.nav-section');
            const subsections = document.querySelectorAll('.nav-subsection');
            
            if (searchTerm === '') {{
                // Show all items when search is empty
                navItems.forEach(item => {{
                    item.style.display = 'flex';
                }});
                sections.forEach(section => {{
                    section.style.display = 'block';
                }});
                subsections.forEach(subsection => {{
                    subsection.style.display = 'block';
                }});
                return;
            }}
            
            let hasVisibleItems = false;
            
            // Hide all sections first
            sections.forEach(section => {{
                section.style.display = 'none';
            }});
            
            subsections.forEach(subsection => {{
                subsection.style.display = 'none';
            }});
            
            navItems.forEach(item => {{
                const searchData = item.getAttribute('data-search') || '';
                if (searchData.toLowerCase().includes(searchTerm)) {{
                    item.style.display = 'flex';
                    hasVisibleItems = true;
                    
                    // Show parent section and subsection
                    let parent = item.closest('.nav-section');
                    if (parent) {{
                        parent.style.display = 'block';
                        // Expand the section
                        const content = parent.querySelector('.nav-content');
                        if (content) content.style.display = 'block';
                    }}
                    
                    let parentSub = item.closest('.nav-subsection');
                    if (parentSub) {{
                        parentSub.style.display = 'block';
                        // Expand the subsection
                        const content = parentSub.querySelector('.nav-subcontent');
                        if (content) content.style.display = 'block';
                    }}
                }} else {{
                    item.style.display = 'none';
                }}
            }});
            
            if (!hasVisibleItems) {{
                // Show "no results" message
                document.getElementById('reportContent').innerHTML = `
                    <div class="alert alert-info">
                        <h4>Nenhum resultado encontrado</h4>
                        <p>Não foram encontrados resultados para "<strong>${{searchTerm}}</strong>".</p>
                        <p>Tente buscar por IPs, domínios ou portas.</p>
                    </div>
                `;
            }}
        }}
        
        // Initialize - show all sections expanded by default
        document.addEventListener('DOMContentLoaded', function() {{
            document.querySelectorAll('.nav-content').forEach(content => {{
                content.style.display = 'block';
            }});
            document.querySelectorAll('.nav-subcontent').forEach(content => {{
                content.style.display = 'block';
            }});
        }});
    </script>
</body>
</html>"""

        index_path = os.path.join(self.report_dir, "index.html")
        with open(index_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"Master index generated: {index_path}")
        return index_path

    def generate_target_report(self, target_name, target_data):
        """Generate individual target report"""
        target_safe = target_name.replace('.', '_')
        target_dir = os.path.join(self.report_dir, target_safe)
        os.makedirs(target_dir, exist_ok=True)
        
        # Generate HTML reports from Nmap XMLs
        nmap_reports = []
        fingerprint_path = target_data['fingerprint']
        
        if os.path.exists(fingerprint_path):
            # Find all Nmap XML files
            xml_files = glob.glob(os.path.join(fingerprint_path, "**/*.xml"), recursive=True)
            for xml_file in xml_files:
                if "nmap" in os.path.basename(xml_file):
                    html_report = self.generate_html_from_nmap_xml(xml_file, target_safe)
                    if html_report:
                        nmap_reports.append({
                            'name': os.path.basename(html_report),
                            'path': os.path.relpath(html_report, target_dir),
                            'type': 'nmap'
                        })

        # Generate target-specific index
        target_html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório - {target_name}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container-fluid py-4">
        <h1>Relatório de Segurança - {target_name}</h1>
        
        <div class="row mt-4">
            <div class="col-12">
                <h3>Relatórios Nmap Disponíveis</h3>
                <div class="list-group">
"""
        
        for report in nmap_reports:
            target_html += f"""
                    <a href="{report['path']}" class="list-group-item list-group-item-action" target="_blank">
                        <div class="d-flex w-100 justify-content-between">
                            <h5 class="mb-1">{report['name']}</h5>
                            <small class="text-muted">{report['type'].upper()}</small>
                        </div>
                        <p class="mb-1">Relatório detalhado de varredura de portas e serviços</p>
                    </a>
"""
        
        target_html += """
                </div>
            </div>
        </div>
    </div>
    
    <footer class="footer mt-5" style="padding: 20px 0; background: #f8f9fa; border-top: 1px solid #dee2e6;">
        <div class="container">
            <p class="text-muted text-center" style="margin: 0; font-size: 12px; color: #777;">
                Documento confidencial - Este relatório foi gerado pela <a href="https://maltauromartins.com">MaltauroMartins</a> para Directcall. <br/>
                Relatório Técnico de Segurança Cibernética - Gerado em """ + datetime.now().strftime("%d/%m/%Y") + """.<br/>
                <a href="https://maltauromartins.com" target="_blank" style="color: #555; text-decoration: none;">MaltauroMartins Soluções Tecnológicas</a>
            </p>
        </div>
    </footer>
</body>
</html>"""

        target_index_path = os.path.join(target_dir, "index.html")
        with open(target_index_path, 'w', encoding='utf-8') as f:
            f.write(target_html)
        
        logger.info(f"Target report generated: {target_index_path}")

    def generate_all_reports(self, target_filter=None):
        """Generate all reports"""
        logger.info("Starting unified report generation...")
        
        # Discover all targets
        targets = self.discover_targets()
        
        if target_filter:
            targets = {k: v for k, v in targets.items() if target_filter in k}
        
        if not targets:
            logger.warning("No targets found for report generation")
            return
        
        logger.info(f"Found {len(targets)} targets: {list(targets.keys())}")
        
        # Generate individual target reports
        for target_name, target_data in targets.items():
            logger.info(f"Generating report for: {target_name}")
            self.generate_target_report(target_name, target_data)
        
        # Generate master index
        self.generate_master_index(targets)
        
        logger.info(f"All reports generated successfully in: {self.report_dir}")

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