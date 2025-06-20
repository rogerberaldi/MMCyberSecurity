#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import argparse
import logging
import glob
import re
import datetime
import xml.etree.ElementTree as ET
from pathlib import Path
from collections import defaultdict
import subprocess

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class UnifiedReportGenerator:
    def __init__(self, output_base_dir="output", report_dir="output/report"):
        self.output_base_dir = Path(output_base_dir)
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        
        # Create assets directory for logo and CSS
        self.assets_dir = self.report_dir / "assets"
        self.assets_dir.mkdir(exist_ok=True)
        
        self.targets_data = {}
        self.current_date = datetime.date.today().strftime("%d/%m/%Y")
        
    def scan_output_directory(self):
        """Scan the output directory and organize data by target"""
        logger.info("Scanning output directory for targets...")
        
        # Find all target directories (domains/IPs)
        for target_path in self.output_base_dir.iterdir():
            if target_path.is_dir() and target_path.name != "report":
                target_name = target_path.name
                logger.info(f"Processing target: {target_name}")
                
                self.targets_data[target_name] = {
                    'footprint': {},
                    'fingerprint': {},
                    'ips': set(),
                    'domains': set(),
                    'ports': set(),
                    'services': {},
                    'vulnerabilities': [],
                    'web_technologies': {}
                }
                
                # Process footprint data
                footprint_dir = target_path / "footprint"
                if footprint_dir.exists():
                    self._process_footprint_data(target_name, footprint_dir)
                
                # Process fingerprint data
                fingerprint_dir = target_path / "fingerprint"
                if fingerprint_dir.exists():
                    self._process_fingerprint_data(target_name, fingerprint_dir)
    
    def _process_footprint_data(self, target_name, footprint_dir):
        """Process footprint scan data"""
        target_data = self.targets_data[target_name]['footprint']
        
        # DNS enumeration
        dns_file = footprint_dir / "dns_enumeration.json"
        if dns_file.exists():
            try:
                with open(dns_file, 'r') as f:
                    target_data['dns'] = json.load(f)
            except json.JSONDecodeError as e:
                logger.error(f"Error reading DNS data for {target_name}: {e}")
        
        # WHOIS data
        whois_file = footprint_dir / "whois.txt"
        if whois_file.exists():
            with open(whois_file, 'r') as f:
                target_data['whois'] = f.read()
        
        # IP/ASN mapping
        ip_asn_file = footprint_dir / "ip_asn.json"
        if ip_asn_file.exists():
            try:
                with open(ip_asn_file, 'r') as f:
                    ip_asn_data = json.load(f)
                    target_data['ip_asn'] = ip_asn_data
                    # Extract IPs
                    for item in ip_asn_data:
                        if 'ip' in item:
                            self.targets_data[target_name]['ips'].add(item['ip'])
            except json.JSONDecodeError as e:
                logger.error(f"Error reading IP/ASN data for {target_name}: {e}")
        
        # Subdomains
        subdomains_file = footprint_dir / "all_subdomains.txt"
        if subdomains_file.exists():
            with open(subdomains_file, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
                target_data['subdomains'] = subdomains
                self.targets_data[target_name]['domains'].update(subdomains)
        
        # Geolocation
        geo_file = footprint_dir / "geolocation.json"
        if geo_file.exists():
            try:
                with open(geo_file, 'r') as f:
                    target_data['geolocation'] = json.load(f)
            except json.JSONDecodeError as e:
                logger.error(f"Error reading geolocation data for {target_name}: {e}")
    
    def _process_fingerprint_data(self, target_name, fingerprint_dir):
        """Process fingerprint scan data"""
        target_data = self.targets_data[target_name]['fingerprint']
        
        # Consolidated ports
        ports_file = fingerprint_dir / "consolidated_open_tcp_ports_by_ip.json"
        if ports_file.exists():
            try:
                with open(ports_file, 'r') as f:
                    ports_data = json.load(f)
                    target_data['ports'] = ports_data
                    
                    # Extract IPs and ports
                    for ip, ports in ports_data.items():
                        self.targets_data[target_name]['ips'].add(ip)
                        self.targets_data[target_name]['ports'].update(ports)
            except json.JSONDecodeError as e:
                logger.error(f"Error reading ports data for {target_name}: {e}")
        
        # Service enumeration XMLs
        service_xmls = list(fingerprint_dir.rglob("service_scan_*.xml"))
        target_data['service_scans'] = []
        
        for xml_file in service_xmls:
            services = self._parse_nmap_service_xml(xml_file)
            if services:
                target_data['service_scans'].append({
                    'file': str(xml_file.relative_to(self.output_base_dir)),
                    'services': services
                })
                
                # Extract services for correlation
                for service in services:
                    ip = service.get('ip', 'unknown')
                    port = service.get('port', 'unknown')
                    service_name = service.get('name', 'unknown')
                    
                    if ip not in self.targets_data[target_name]['services']:
                        self.targets_data[target_name]['services'][ip] = {}
                    self.targets_data[target_name]['services'][ip][port] = service_name
        
        # Web technology scans
        web_tech_files = list(fingerprint_dir.rglob("web_technologies_consolidated.json"))
        for web_file in web_tech_files:
            try:
                with open(web_file, 'r') as f:
                    web_data = json.load(f)
                    target_data['web_technologies'] = web_data
                    self.targets_data[target_name]['web_technologies'].update(web_data)
            except json.JSONDecodeError as e:
                logger.error(f"Error reading web tech data for {target_name}: {e}")
        
        # Nuclei vulnerability scans
        nuclei_files = list(fingerprint_dir.rglob("nuclei_vulns_*.json"))
        vulnerabilities = []
        
        for nuclei_file in nuclei_files:
            vulns = self._parse_nuclei_vulnerabilities(nuclei_file)
            vulnerabilities.extend(vulns)
        
        target_data['vulnerabilities'] = vulnerabilities
        self.targets_data[target_name]['vulnerabilities'].extend(vulnerabilities)
    
    def _parse_nmap_service_xml(self, xml_file):
        """Parse Nmap service scan XML"""
        services = []
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host in root.findall('host'):
                host_ip = None
                address_elem = host.find('address')
                if address_elem is not None:
                    host_ip = address_elem.get('addr')
                
                for port_elem in host.findall('ports/port'):
                    port_id = port_elem.get('portid')
                    protocol = port_elem.get('protocol')
                    
                    state_elem = port_elem.find('state')
                    state = state_elem.get('state') if state_elem is not None else 'unknown'
                    
                    service_elem = port_elem.find('service')
                    service_info = {
                        'ip': host_ip,
                        'port': port_id,
                        'protocol': protocol,
                        'state': state
                    }
                    
                    if service_elem is not None:
                        service_info.update({
                            'name': service_elem.get('name', ''),
                            'product': service_elem.get('product', ''),
                            'version': service_elem.get('version', ''),
                            'extrainfo': service_elem.get('extrainfo', '')
                        })
                    
                    services.append(service_info)
        
        except ET.ParseError as e:
            logger.error(f"Error parsing XML {xml_file}: {e}")
        
        return services
    
    def _parse_nuclei_vulnerabilities(self, nuclei_file):
        """Parse Nuclei vulnerability JSON files"""
        vulnerabilities = []
        
        if not nuclei_file.exists() or nuclei_file.stat().st_size == 0:
            return vulnerabilities
        
        try:
            with open(nuclei_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            vuln_data = json.loads(line)
                            
                            # Extract vulnerability information
                            vuln = {
                                'template_id': vuln_data.get('template-id', ''),
                                'name': vuln_data.get('info', {}).get('name', ''),
                                'severity': vuln_data.get('info', {}).get('severity', 'info'),
                                'host': vuln_data.get('host', ''),
                                'matched_at': vuln_data.get('matched-at', ''),
                                'timestamp': vuln_data.get('timestamp', ''),
                                'description': vuln_data.get('info', {}).get('description', ''),
                                'tags': vuln_data.get('info', {}).get('tags', [])
                            }
                            
                            vulnerabilities.append(vuln)
                            
                        except json.JSONDecodeError as e:
                            logger.debug(f"Error parsing line in {nuclei_file}: {e}")
                            continue
        
        except Exception as e:
            logger.error(f"Error reading nuclei file {nuclei_file}: {e}")
        
        return vulnerabilities
    
    def generate_target_html_report(self, target_name):
        """Generate HTML report for a specific target"""
        target_data = self.targets_data[target_name]
        
        # Create target-specific directory
        target_report_dir = self.report_dir / target_name
        target_report_dir.mkdir(exist_ok=True)
        
        # Generate HTML content
        html_content = self._generate_target_html_content(target_name, target_data)
        
        # Write HTML file
        html_file = target_report_dir / "index.html"
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"Generated HTML report for {target_name}: {html_file}")
        return html_file
    
    def _generate_target_html_content(self, target_name, target_data):
        """Generate HTML content for target report"""
        
        # Get vulnerability counts by severity
        vuln_counts = defaultdict(int)
        for vuln in target_data['vulnerabilities']:
            severity = vuln.get('severity', 'info')
            vuln_counts[severity] += 1
        
        # Generate sections
        footprint_section = self._generate_footprint_html_section(target_data.get('footprint', {}))
        fingerprint_section = self._generate_fingerprint_html_section(target_data.get('fingerprint', {}))
        vulnerability_section = self._generate_vulnerability_html_section(target_data['vulnerabilities'])
        correlation_section = self._generate_correlation_html_section(target_data)
        
        html_content = f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MaltauroMartins - CyberSecurity Report - {target_name}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .severity-critical {{ background-color: #dc3545; color: white; }}
        .severity-high {{ background-color: #fd7e14; color: white; }}
        .severity-medium {{ background-color: #ffc107; color: black; }}
        .severity-low {{ background-color: #20c997; color: white; }}
        .severity-info {{ background-color: #0dcaf0; color: black; }}
        .port-matrix {{ font-size: 0.8em; }}
        .port-matrix td {{ padding: 2px 4px; }}
        .service-open {{ background-color: #d4edda; }}
        .service-filtered {{ background-color: #fff3cd; }}
        .service-closed {{ background-color: #f8d7da; }}
        .collapsible-section {{ margin-bottom: 20px; }}
        .search-box {{ margin-bottom: 15px; }}
    </style>
</head>
<body>
    <!-- Header -->
    <header class="bg-dark text-white py-3">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-md-2">
                    <img src="../assets/logo.png" alt="MaltauroMartins Logo" class="img-fluid" style="max-height: 50px;">
                </div>
                <div class="col-md-10">
                    <h1 class="h3 mb-0">Relatório de Segurança Cibernética - DirectCall - {target_name}</h1>
                </div>
            </div>
        </div>
    </header>

    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <div class="container">
            <div class="navbar-nav">
                <a class="nav-link" href="#overview">Visão Geral</a>
                <a class="nav-link" href="#footprint">Footprint</a>
                <a class="nav-link" href="#fingerprint">Fingerprint</a>
                <a class="nav-link" href="#vulnerabilities">Vulnerabilidades</a>
                <a class="nav-link" href="#correlation">Correlação</a>
            </div>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="container mt-4">
        <!-- Overview Section -->
        <section id="overview" class="mb-5">
            <h2><i class="fas fa-chart-pie"></i> Visão Geral</h2>
            <div class="row">
                <div class="col-md-3">
                    <div class="card text-center">
                        <div class="card-body">
                            <h5 class="card-title">{len(target_data['ips'])}</h5>
                            <p class="card-text">IPs Identificados</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card text-center">
                        <div class="card-body">
                            <h5 class="card-title">{len(target_data['ports'])}</h5>
                            <p class="card-text">Portas Abertas</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card text-center">
                        <div class="card-body">
                            <h5 class="card-title">{len(target_data['domains'])}</h5>
                            <p class="card-text">Domínios/Subdomínios</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card text-center">
                        <div class="card-body">
                            <h5 class="card-title">{len(target_data['vulnerabilities'])}</h5>
                            <p class="card-text">Vulnerabilidades</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Vulnerability Summary -->
            {self._generate_vulnerability_summary_cards(vuln_counts)}
        </section>

        <!-- Search and Filter -->
        <section class="mb-4">
            <div class="row">
                <div class="col-md-4">
                    <input type="text" id="searchIPs" class="form-control" placeholder="Buscar IPs...">
                </div>
                <div class="col-md-4">
                    <input type="text" id="searchPorts" class="form-control" placeholder="Buscar Portas...">
                </div>
                <div class="col-md-4">
                    <input type="text" id="searchDomains" class="form-control" placeholder="Buscar Domínios...">
                </div>
            </div>
        </section>

        {footprint_section}
        {fingerprint_section}
        {vulnerability_section}
        {correlation_section}
    </div>

    <!-- Footer -->
    <footer class="footer bg-light mt-5 py-4">
        <div class="container">
            <p class="text-muted text-center mb-0" style="font-size: 12px;">
                Documento confidencial - Este relatório foi gerado pela <a href="https://maltauromartins.com">MaltauroMartins</a> para Directcall.<br/>
                Relatório Técnico de Segurança Cibernética - Gerado em {self.current_date}.<br/>
                <a href="https://maltauromartins.com" target="_blank" style="color: #555; text-decoration: none;">MaltauroMartins Soluções Tecnológicas</a>
            </p>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Simple search functionality
        function setupSearch() {{
            const searchIPs = document.getElementById('searchIPs');
            const searchPorts = document.getElementById('searchPorts');
            const searchDomains = document.getElementById('searchDomains');
            
            function filterTable(searchInput, columnIndex, tableId) {{
                searchInput.addEventListener('keyup', function() {{
                    const filter = this.value.toLowerCase();
                    const table = document.getElementById(tableId);
                    if (!table) return;
                    
                    const rows = table.getElementsByTagName('tr');
                    for (let i = 1; i < rows.length; i++) {{
                        const cell = rows[i].getElementsByTagName('td')[columnIndex];
                        if (cell) {{
                            const textValue = cell.textContent || cell.innerText;
                            rows[i].style.display = textValue.toLowerCase().indexOf(filter) > -1 ? '' : 'none';
                        }}
                    }}
                }});
            }}
            
            // Apply filters to relevant tables
            filterTable(searchIPs, 0, 'portsTable');
            filterTable(searchPorts, 1, 'portsTable');
            filterTable(searchDomains, 0, 'domainsTable');
        }}
        
        document.addEventListener('DOMContentLoaded', setupSearch);
    </script>
</body>
</html>
        """
        
        return html_content
    
    def _generate_vulnerability_summary_cards(self, vuln_counts):
        """Generate vulnerability summary cards"""
        if not vuln_counts:
            return ""
        
        cards_html = '<div class="row mt-3">'
        
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        severity_icons = {
            'critical': 'fas fa-exclamation-triangle',
            'high': 'fas fa-fire',
            'medium': 'fas fa-exclamation-circle',
            'low': 'fas fa-info-circle',
            'info': 'fas fa-info'
        }
        
        for severity in severity_order:
            if severity in vuln_counts:
                count = vuln_counts[severity]
                icon = severity_icons.get(severity, 'fas fa-question')
                
                cards_html += f'''
                <div class="col-md-2">
                    <div class="card severity-{severity}">
                        <div class="card-body text-center">
                            <i class="{icon} fa-2x mb-2"></i>
                            <h5 class="card-title">{count}</h5>
                            <p class="card-text">{severity.title()}</p>
                        </div>
                    </div>
                </div>
                '''
        
        cards_html += '</div>'
        return cards_html
    
    def _generate_footprint_html_section(self, footprint_data):
        """Generate footprint section HTML"""
        if not footprint_data:
            return ""
        
        # DNS Section
        dns_html = ""
        if 'dns' in footprint_data:
            dns_html = "<h4>DNS Records</h4><div class='table-responsive'><table class='table table-striped'><thead><tr><th>Type</th><th>Records</th></tr></thead><tbody>"
            for record_type, records in footprint_data['dns'].items():
                records_str = ', '.join(records) if isinstance(records, list) else str(records)
                dns_html += f"<tr><td>{record_type}</td><td>{records_str}</td></tr>"
            dns_html += "</tbody></table></div>"
        
        # Subdomains Section
        subdomains_html = ""
        if 'subdomains' in footprint_data:
            subdomains_html = f"<h4>Subdomínios ({len(footprint_data['subdomains'])})</h4>"
            subdomains_html += "<div class='table-responsive'><table id='domainsTable' class='table table-striped'><thead><tr><th>Subdomínio</th></tr></thead><tbody>"
            for subdomain in footprint_data['subdomains']:
                subdomains_html += f"<tr><td>{subdomain}</td></tr>"
            subdomains_html += "</tbody></table></div>"
        
        # IP/ASN Section
        ip_asn_html = ""
        if 'ip_asn' in footprint_data:
            ip_asn_html = "<h4>IP/ASN Information</h4><div class='table-responsive'><table class='table table-striped'><thead><tr><th>IP</th><th>ASN</th><th>Network</th><th>Country</th></tr></thead><tbody>"
            for item in footprint_data['ip_asn']:
                ip = item.get('ip', 'N/A')
                asn = item.get('asn', 'N/A')
                network = item.get('network', {}).get('name', 'N/A')
                country = item.get('asn_country_code', 'N/A')
                ip_asn_html += f"<tr><td>{ip}</td><td>{asn}</td><td>{network}</td><td>{country}</td></tr>"
            ip_asn_html += "</tbody></table></div>"
        
        return f"""
        <section id="footprint" class="mb-5">
            <h2><i class="fas fa-search"></i> Footprint Analysis</h2>
            <div class="collapsible-section">
                {dns_html}
                {subdomains_html}
                {ip_asn_html}
            </div>
        </section>
        """
    
    def _generate_fingerprint_html_section(self, fingerprint_data):
        """Generate fingerprint section HTML"""
        if not fingerprint_data:
            return ""
        
        # Ports Summary
        ports_html = ""
        if 'ports' in fingerprint_data:
            ports_html = "<h4>Open Ports by IP</h4><div class='table-responsive'><table id='portsTable' class='table table-striped'><thead><tr><th>IP Address</th><th>Open Ports</th><th>Port Count</th></tr></thead><tbody>"
            for ip, ports in fingerprint_data['ports'].items():
                ports_str = ', '.join(map(str, sorted(ports)))
                ports_html += f"<tr><td>{ip}</td><td>{ports_str}</td><td>{len(ports)}</td></tr>"
            ports_html += "</tbody></table></div>"
        
        # Services Summary
        services_html = ""
        if 'service_scans' in fingerprint_data:
            services_html = "<h4>Detected Services</h4><div class='table-responsive'><table class='table table-striped'><thead><tr><th>IP</th><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr></thead><tbody>"
            for scan in fingerprint_data['service_scans']:
                for service in scan['services']:
                    if service.get('state') == 'open':
                        services_html += f"""
                        <tr class="service-open">
                            <td>{service.get('ip', 'N/A')}</td>
                            <td>{service.get('port', 'N/A')}</td>
                            <td>{service.get('name', 'N/A')}</td>
                            <td>{service.get('product', 'N/A')}</td>
                            <td>{service.get('version', 'N/A')}</td>
                        </tr>
                        """
            services_html += "</tbody></table></div>"
        
        # Web Technologies
        web_tech_html = ""
        if 'web_technologies' in fingerprint_data:
            web_tech_html = "<h4>Web Technologies</h4>"
            for ip, ports_data in fingerprint_data['web_technologies'].items():
                web_tech_html += f"<h5>IP: {ip}</h5>"
                for port, tech_data in ports_data.items():
                    web_tech_html += f"<h6>Port {port}</h6>"
                    if 'nmap_info' in tech_data:
                        nmap_info = tech_data['nmap_info']
                        web_tech_html += f"<p><strong>Service:</strong> {nmap_info.get('name', 'N/A')} - {nmap_info.get('product', 'N/A')}</p>"
                    
                    if 'nuclei_tech_results' in tech_data and tech_data['nuclei_tech_results']:
                        web_tech_html += "<p><strong>Technologies detected:</strong></p><ul>"
                        for tech in tech_data['nuclei_tech_results']:
                            tech_name = tech.get('info', {}).get('name', 'Unknown')
                            web_tech_html += f"<li>{tech_name}</li>"
                        web_tech_html += "</ul>"
        
        return f"""
        <section id="fingerprint" class="mb-5">
            <h2><i class="fas fa-fingerprint"></i> Fingerprint Analysis</h2>
            <div class="collapsible-section">
                {ports_html}
                {services_html}
                {web_tech_html}
            </div>
        </section>
        """
    
    def _generate_vulnerability_html_section(self, vulnerabilities):
        """Generate vulnerabilities section HTML"""
        if not vulnerabilities:
            return """
            <section id="vulnerabilities" class="mb-5">
                <h2><i class="fas fa-shield-alt"></i> Vulnerabilities</h2>
                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i> No vulnerabilities detected.
                </div>
            </section>
            """
        
        # Group vulnerabilities by severity
        vuln_by_severity = defaultdict(list)
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info')
            vuln_by_severity[severity].append(vuln)
        
        vuln_html = ""
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        
        for severity in severity_order:
            if severity in vuln_by_severity:
                vuln_list = vuln_by_severity[severity]
                vuln_html += f"""
                <h4 class="severity-{severity} p-2 rounded">
                    <i class="fas fa-exclamation-triangle"></i> {severity.title()} ({len(vuln_list)})
                </h4>
                <div class="table-responsive mb-4">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Host</th>
                                <th>Template ID</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>
                """
                
                for vuln in vuln_list:
                    vuln_html += f"""
                    <tr>
                        <td>{vuln.get('name', 'N/A')}</td>
                        <td>{vuln.get('host', 'N/A')}</td>
                        <td><code>{vuln.get('template_id', 'N/A')}</code></td>
                        <td>{vuln.get('description', 'N/A')[:100]}...</td>
                    </tr>
                    """
                
                vuln_html += "</tbody></table></div>"
        
        return f"""
        <section id="vulnerabilities" class="mb-5">
            <h2><i class="fas fa-shield-alt"></i> Vulnerabilities</h2>
            <div class="collapsible-section">
                {vuln_html}
            </div>
        </section>
        """
    
    def _generate_correlation_html_section(self, target_data):
        """Generate correlation matrix section"""
        services = target_data.get('services', {})
        if not services:
            return ""
        
        # Create port/service correlation matrix
        all_ports = set()
        for ip_services in services.values():
            all_ports.update(ip_services.keys())
        
        all_ports = sorted(all_ports, key=lambda x: int(x) if x.isdigit() else 999999)
        
        matrix_html = """
        <h4>Port/Service Correlation Matrix</h4>
        <div class="table-responsive">
            <table class="table table-bordered port-matrix">
                <thead>
                    <tr>
                        <th>IP Address</th>
        """
        
        for port in all_ports:
            matrix_html += f"<th>{port}</th>"
        
        matrix_html += "</tr></thead><tbody>"
        
        for ip in sorted(services.keys()):
            matrix_html += f"<tr><td><strong>{ip}</strong></td>"
            for port in all_ports:
                service_name = services[ip].get(port, '')
                cell_class = "service-open" if service_name else "service-closed"
                display_text = service_name[:8] if service_name else '-'
                matrix_html += f'<td class="{cell_class}" title="{service_name}">{display_text}</td>'
            matrix_html += "</tr>"
        
        matrix_html += "</tbody></table></div>"
        
        return f"""
        <section id="correlation" class="mb-5">
            <h2><i class="fas fa-project-diagram"></i> Service Correlation</h2>
            <div class="collapsible-section">
                {matrix_html}
            </div>
        </section>
        """
    
    def generate_latex_report(self, target_name):
        """Generate LaTeX report for a specific target"""
        target_data = self.targets_data[target_name]
        
        # Create target-specific directory
        target_report_dir = self.report_dir / target_name
        target_report_dir.mkdir(exist_ok=True)
        
        latex_content = self._generate_latex_content(target_name, target_data)
        
        # Write LaTeX file
        latex_file = target_report_dir / f"{target_name.replace('.', '_')}.tex"
        with open(latex_file, 'w', encoding='utf-8') as f:
            f.write(latex_content)
        
        logger.info(f"Generated LaTeX report for {target_name}: {latex_file}")
        return latex_file
    
    def _generate_latex_content(self, target_name, target_data):
        """Generate LaTeX content for target report"""
        
        # Required packages
        packages = [
            "\\usepackage{hyperref}",
            "\\usepackage{longtable}",
            "\\usepackage{booktabs}",
            "\\usepackage{array}",
            "\\usepackage{xcolor}",
            "\\usepackage{graphicx}",
            "\\usepackage{tabularx}",
            "\\usepackage{multicol}"
        ]
        
        packages_section = "% Required packages:\n" + "\n".join([f"% {pkg}" for pkg in packages])
        
        # Generate sections
        footprint_section = self._generate_footprint_latex_section(target_data.get('footprint', {}))
        fingerprint_section = self._generate_fingerprint_latex_section(target_data.get('fingerprint', {}))
        vulnerability_section = self._generate_vulnerability_latex_section(target_data['vulnerabilities'])
        
        latex_content = f"""
{packages_section}

\\section{{Relatório de Segurança Cibernética - {target_name.replace('_', '\\_')}}}

\\subsection{{Resumo Executivo}}

Este relatório apresenta os resultados da análise de segurança cibernética realizada para o alvo \\texttt{{{target_name.replace('_', '\\_')}}}.

\\begin{{itemize}}
\\item \\textbf{{IPs Identificados:}} {len(target_data['ips'])}
\\item \\textbf{{Portas Abertas:}} {len(target_data['ports'])}
\\item \\textbf{{Domínios/Subdomínios:}} {len(target_data['domains'])}
\\item \\textbf{{Vulnerabilidades:}} {len(target_data['vulnerabilities'])}
\\end{{itemize}}

{footprint_section}

{fingerprint_section}

{vulnerability_section}

\\subsection{{Conclusões}}

A análise identificou {len(target_data['ips'])} endereços IP associados ao alvo, com {len(target_data['ports'])} portas abertas e {len(target_data['vulnerabilities'])} vulnerabilidades detectadas.

\\textbf{{Recomendações:}}
\\begin{{itemize}}
\\item Revisar e corrigir as vulnerabilidades identificadas
\\item Implementar monitoramento contínuo de segurança
\\item Realizar testes de penetração regulares
\\end{{itemize}}
        """
        
        return latex_content
    
    def _generate_footprint_latex_section(self, footprint_data):
        """Generate footprint section for LaTeX"""
        if not footprint_data:
            return ""
        
        section = "\\subsection{Análise de Footprint}\n\n"
        
        # DNS Records
        if 'dns' in footprint_data:
            section += "\\subsubsection{Registros DNS}\n\n"
            section += "\\begin{longtable}{|l|p{10cm}|}\n"
            section += "\\hline\n"
            section += "\\textbf{Tipo} & \\textbf{Registros} \\\\ \\hline\n"
            
            for record_type, records in footprint_data['dns'].items():
                records_str = ', '.join(records) if isinstance(records, list) else str(records)
                records_str = records_str.replace('_', '\\_').replace('&', '\\&')
                section += f"{record_type} & {records_str} \\\\ \\hline\n"
            
            section += "\\end{longtable}\n\n"
        
        # Subdomains
        if 'subdomains' in footprint_data:
            section += f"\\subsubsection{{Subdomínios ({len(footprint_data['subdomains'])})}}\n\n"
            section += "\\begin{multicols}{2}\n"
            section += "\\begin{itemize}\n"
            
            for subdomain in footprint_data['subdomains'][:50]:  # Limit to first 50
                subdomain_escaped = subdomain.replace('_', '\\_').replace('&', '\\&')
                section += f"\\item \\texttt{{{subdomain_escaped}}}\n"
            
            if len(footprint_data['subdomains']) > 50:
                section += f"\\item ... e mais {len(footprint_data['subdomains']) - 50} subdomínios\n"
            
            section += "\\end{itemize}\n"
            section += "\\end{multicols}\n\n"
        
        return section
    
    def _generate_fingerprint_latex_section(self, fingerprint_data):
        """Generate fingerprint section for LaTeX"""
        if not fingerprint_data:
            return ""
        
        section = "\\subsection{Análise de Fingerprint}\n\n"
        
        # Ports Summary
        if 'ports' in fingerprint_data:
            section += "\\subsubsection{Portas Abertas por IP}\n\n"
            section += "\\begin{longtable}{|l|p{8cm}|c|}\n"
            section += "\\hline\n"
            section += "\\textbf{Endereço IP} & \\textbf{Portas Abertas} & \\textbf{Total} \\\\ \\hline\n"
            
            for ip, ports in fingerprint_data['ports'].items():
                ports_str = ', '.join(map(str, sorted(ports)))
                if len(ports_str) > 60:
                    ports_str = ports_str[:60] + "..."
                section += f"{ip} & {ports_str} & {len(ports)} \\\\ \\hline\n"
            
            section += "\\end{longtable}\n\n"
        
        # Services Summary
        if 'service_scans' in fingerprint_data:
            section += "\\subsubsection{Serviços Detectados}\n\n"
            section += "\\begin{longtable}{|l|c|l|l|l|}\n"
            section += "\\hline\n"
            section += "\\textbf{IP} & \\textbf{Porta} & \\textbf{Serviço} & \\textbf{Produto} & \\textbf{Versão} \\\\ \\hline\n"
            
            for scan in fingerprint_data['service_scans']:
                for service in scan['services']:
                    if service.get('state') == 'open':
                        ip = service.get('ip', 'N/A')
                        port = service.get('port', 'N/A')
                        name = service.get('name', 'N/A').replace('_', '\\_')
                        product = service.get('product', 'N/A').replace('_', '\\_')
                        version = service.get('version', 'N/A').replace('_', '\\_')
                        
                        section += f"{ip} & {port} & {name} & {product} & {version} \\\\ \\hline\n"
            
            section += "\\end{longtable}\n\n"
        
        return section
    
    def _generate_vulnerability_latex_section(self, vulnerabilities):
        """Generate vulnerabilities section for LaTeX"""
        if not vulnerabilities:
            return "\\subsection{Vulnerabilidades}\n\nNenhuma vulnerabilidade foi detectada durante a análise.\n\n"
        
        section = "\\subsection{Vulnerabilidades}\n\n"
        
        # Group by severity
        vuln_by_severity = defaultdict(list)
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info')
            vuln_by_severity[severity].append(vuln)
        
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        severity_colors = {
            'critical': 'red',
            'high': 'orange',
            'medium': 'yellow',
            'low': 'green',
            'info': 'blue'
        }
        
        for severity in severity_order:
            if severity in vuln_by_severity:
                vuln_list = vuln_by_severity[severity]
                color = severity_colors.get(severity, 'black')
                
                section += f"\\subsubsection{{\\textcolor{{{color}}}{{{severity.title()} ({len(vuln_list)})}}}}\n\n"
                section += "\\begin{longtable}{|p{4cm}|p{3cm}|p{6cm}|}\n"
                section += "\\hline\n"
                section += "\\textbf{Nome} & \\textbf{Host} & \\textbf{Descrição} \\\\ \\hline\n"
                
                for vuln in vuln_list:
                    name = vuln.get('name', 'N/A').replace('_', '\\_').replace('&', '\\&')
                    host = vuln.get('host', 'N/A').replace('_', '\\_')
                    description = vuln.get('description', 'N/A').replace('_', '\\_').replace('&', '\\&')
                    
                    # Truncate long descriptions
                    if len(description) > 100:
                        description = description[:100] + "..."
                    
                    section += f"{name} & {host} & {description} \\\\ \\hline\n"
                
                section += "\\end{longtable}\n\n"
        
        return section
    
    def generate_master_index(self):
        """Generate master index.html with frame navigation"""
        
        # Copy logo if it exists
        logo_source = Path("logo.png")
        logo_dest = self.assets_dir / "logo.png"
        if logo_source.exists():
            import shutil
            shutil.copy2(logo_source, logo_dest)
        
        # Generate navigation tree
        nav_tree = self._generate_navigation_tree()
        
        # Create main index.html
        index_content = f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MaltauroMartins - CyberSecurity Report</title>
    <style>
        body, html {{
            margin: 0;
            padding: 0;
            height: 100%;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }}
        
        .header {{
            height: 80px;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            display: flex;
            align-items: center;
            padding: 0 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        .header img {{
            height: 50px;
            margin-right: 20px;
        }}
        
        .header h1 {{
            margin: 0;
            font-size: 24px;
            font-weight: 300;
        }}
        
        .container {{
            display: flex;
            height: calc(100vh - 80px);
        }}
        
        .sidebar {{
            width: 300px;
            background: #f8f9fa;
            border-right: 1px solid #dee2e6;
            overflow-y: auto;
            padding: 20px;
        }}
        
        .content {{
            flex: 1;
            background: white;
        }}
        
        .content iframe {{
            width: 100%;
            height: 100%;
            border: none;
        }}
        
        .nav-tree {{
            list-style: none;
            padding: 0;
            margin: 0;
        }}
        
        .nav-tree li {{
            margin: 5px 0;
        }}
        
        .nav-tree a {{
            display: block;
            padding: 8px 12px;
            text-decoration: none;
            color: #495057;
            border-radius: 4px;
            transition: all 0.2s;
        }}
        
        .nav-tree a:hover {{
            background: #e9ecef;
            color: #212529;
        }}
        
        .nav-tree a.active {{
            background: #007bff;
            color: white;
        }}
        
        .nav-group {{
            margin: 15px 0;
        }}
        
        .nav-group-title {{
            font-weight: bold;
            color: #6c757d;
            margin-bottom: 8px;
            padding: 5px 0;
            border-bottom: 1px solid #dee2e6;
        }}
        
        .nav-subitem {{
            padding-left: 20px;
        }}
        
        .search-box {{
            width: 100%;
            padding: 8px 12px;
            border: 1px solid #ced4da;
            border-radius: 4px;
            margin-bottom: 20px;
            font-size: 14px;
        }}
        
        .footer {{
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            height: 60px;
            background: #f8f9fa;
            border-top: 1px solid #dee2e6;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
            color: #6c757d;
            z-index: 1000;
        }}
        
        .container {{
            height: calc(100vh - 140px); /* Adjust for header and footer */
        }}
    </style>
</head>
<body>
    <!-- Header -->
    <div class="header">
        <img src="assets/logo.png" alt="MaltauroMartins Logo" onerror="this.style.display='none'">
        <h1>Relatório de Segurança Cibernética - DirectCall</h1>
    </div>
    
    <!-- Main Container -->
    <div class="container">
        <!-- Sidebar Navigation -->
        <div class="sidebar">
            <input type="text" class="search-box" id="searchBox" placeholder="Buscar relatórios...">
            <nav>
                {nav_tree}
            </nav>
        </div>
        
        <!-- Content Frame -->
        <div class="content">
            <iframe id="contentFrame" src="about:blank"></iframe>
        </div>
    </div>
    
    <!-- Footer -->
    <div class="footer">
        <p>
            Documento confidencial - Este relatório foi gerado pela 
            <a href="https://maltauromartins.com" target="_blank">MaltauroMartins</a> para Directcall.<br/>
            Relatório Técnico de Segurança Cibernética - Gerado em {self.current_date}.<br/>
            <a href="https://maltauromartins.com" target="_blank">MaltauroMartins Soluções Tecnológicas</a>
        </p>
    </div>
    
    <script>
        // Navigation functionality
        function loadContent(url, element) {{
            document.getElementById('contentFrame').src = url;
            
            // Update active state
            document.querySelectorAll('.nav-tree a').forEach(a => a.classList.remove('active'));
            element.classList.add('active');
        }}
        
        // Search functionality
        document.getElementById('searchBox').addEventListener('input', function() {{
            const filter = this.value.toLowerCase();
            const navItems = document.querySelectorAll('.nav-tree a');
            
            navItems.forEach(item => {{
                const text = item.textContent.toLowerCase();
                const parent = item.closest('li');
                parent.style.display = text.includes(filter) ? 'block' : 'none';
            }});
        }});
        
        // Load default content
        window.addEventListener('load', function() {{
            const firstLink = document.querySelector('.nav-tree a');
            if (firstLink) {{
                loadContent(firstLink.getAttribute('onclick').match(/'([^']+)'/)[1], firstLink);
            }}
        }});
    </script>
</body>
</html>
        """
        
        # Write master index
        index_file = self.report_dir / "index.html"
        with open(index_file, 'w', encoding='utf-8') as f:
            f.write(index_content)
        
        logger.info(f"Generated master index: {index_file}")
        return index_file
    
    def _generate_navigation_tree(self):
        """Generate navigation tree HTML"""
        nav_html = '<ul class="nav-tree">'
        
        for target_name in sorted(self.targets_data.keys()):
            target_data = self.targets_data[target_name]
            
            nav_html += f'''
            <li class="nav-group">
                <div class="nav-group-title">{target_name}</div>
                <ul class="nav-tree">
                    <li><a href="#" onclick="loadContent('{target_name}/index.html', this)">📊 Relatório Completo</a></li>
            '''
            
            # Add IP-specific reports
            for ip in sorted(target_data['ips']):
                ip_safe = ip.replace('.', '_').replace(':', '_')
                
                # Check for existing Nmap HTML reports
                nmap_files = list(self.output_base_dir.glob(f"**/*{ip_safe}*.html"))
                if nmap_files:
                    nav_html += f'<li class="nav-subitem"><a href="#" onclick="loadContent(\'../output/{nmap_files[0].relative_to(self.output_base_dir)}\', this)">🔍 {ip} - Nmap Scan</a></li>'
                
                # Check for service scans
                service_files = list(self.output_base_dir.glob(f"**/service_scan_{ip_safe}.html"))
                if service_files:
                    nav_html += f'<li class="nav-subitem"><a href="#" onclick="loadContent(\'../output/{service_files[0].relative_to(self.output_base_dir)}\', this)">⚙️ {ip} - Services</a></li>'
            
            # Add web scan reports
            web_scan_files = list(self.output_base_dir.glob(f"{target_name}/**/web_scans/**/*.html"))
            for web_file in web_scan_files:
                web_name = web_file.stem
                nav_html += f'<li class="nav-subitem"><a href="#" onclick="loadContent(\'../output/{web_file.relative_to(self.output_base_dir)}\', this)">🌐 {web_name}</a></li>'
            
            nav_html += '</ul></li>'
        
        nav_html += '</ul>'
        return nav_html
    
    def generate_all_reports(self):
        """Generate all reports for all targets"""
        logger.info("Starting unified report generation...")
        
        # Scan output directory
        self.scan_output_directory()
        
        if not self.targets_data:
            logger.warning("No targets found in output directory")
            return
        
        # Generate reports for each target
        for target_name in self.targets_data.keys():
            logger.info(f"Generating reports for {target_name}")
            
            # Generate HTML report
            self.generate_target_html_report(target_name)
            
            # Generate LaTeX report
            self.generate_latex_report(target_name)
        
        # Generate master index
        self.generate_master_index()
        
        logger.info("All reports generated successfully!")
        
        # Print summary
        print(f"\n{'='*60}")
        print("REPORT GENERATION SUMMARY")
        print(f"{'='*60}")
        print(f"Targets processed: {len(self.targets_data)}")
        print(f"Reports location: {self.report_dir}")
        print(f"Master index: {self.report_dir}/index.html")
        print(f"{'='*60}")

def main():
    parser = argparse.ArgumentParser(description="Unified MMCyberSec Report Generator")
    parser.add_argument("--output-dir", default="output", help="Base output directory (default: output)")
    parser.add_argument("--report-dir", default="output/report", help="Report output directory (default: output/report)")
    parser.add_argument("--target", help="Generate report for specific target only")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize generator
    generator = UnifiedReportGenerator(args.output_dir, args.report_dir)
    
    if args.target:
        # Generate report for specific target
        generator.scan_output_directory()
        if args.target in generator.targets_data:
            generator.generate_target_html_report(args.target)
            generator.generate_latex_report(args.target)
            logger.info(f"Report generated for {args.target}")
        else:
            logger.error(f"Target {args.target} not found")
    else:
        # Generate all reports
        generator.generate_all_reports()

if __name__ == "__main__":
    main()