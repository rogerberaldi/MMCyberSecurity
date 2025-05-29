import argparse
import json
import os
from datetime import datetime
import matplotlib.pyplot as plt
import numpy as np

class FootprintReporter:
    def __init__(self, domain, output_dir="reports"):
        self.domain = domain
        self.output_dir = f"{domain}/{output_dir}"
        self.data = {
            'whois': None,
            'dns': None,
            'geo': None,
            'subdomains': None,
            'ip_asn': None
        }
        os.makedirs(f"{domain}/{output_dir}", exist_ok=True)

    def load_data(self, **kwargs):
        """Carrega arquivos de entrada com tratamento de erros."""
        for key, path in kwargs.items():
            try:
                if path.endswith('.json'):
                    with open(path, 'r') as f:
                        self.data[key] = json.load(f)
                elif path.endswith('.txt') and key != 'subdomains':
                    with open(path, 'r') as f:
                        self.data[key] = json.load(f)
                elif key == 'subdomains':
                    with open(path, 'r') as f:
                        self.data[key] = [line.strip() for line in f if line.strip()]
            except (FileNotFoundError, json.JSONDecodeError) as e:
                print(f"[AVISO] Arquivo {path} não encontrado ou inválido: {str(e)}")
                self.data[key] = None

    def generate_section(self, section_name):
        """Gera .tex para cada seção."""
        tex_generators = {
            'whois': self._gen_whois,
            'dns': self._gen_dns,
            'spf': self._gen_spf_analysis,
            'geo': self._gen_geo, 
            'subdomains': self._gen_subdomains,
            'ip_asn': self._gen_ip_asn
        }
        
        content = tex_generators[section_name]()
        with open(f"{self.output_dir}/{self.domain}_{section_name}.tex", 'w') as f:
            f.write(content)

    def _gen_whois(self):
        if not self.data.get('whois'):
            return "\\section{WHOIS}\nDados não disponíveis.\n"
        
        w = self.data['whois']
        return f"""
\\section{{WHOIS}}
\\begin{{tabular}}{{|l|l|}}
\\hline
\\textbf{{Domínio}} & {self.domain} \\\\ \\hline
\\textbf{{Registrante}} & {w.get('registrant_name', 'N/A')} \\\\ \\hline
\\textbf{{CNPJ}} & {w.get('registrant_id', 'N/A')} \\\\ \\hline
\\textbf{{Email}} & \\texttt{{{w.get('email', 'N/A')}}} \\\\ \\hline
\\textbf{{Nameservers}} & {', '.join(w.get('name_server', []))} \\\\ \\hline
\\textbf{{Criação}} & {w.get('creation_date', ['N/A'])[0]} \\\\ \\hline
\\textbf{{Expiração}} & {w.get('expiration_date', 'N/A')} \\\\ \\hline
\\end{{tabular}}
"""

    def is_private_ip(self, ip_str):
        return (
            ip_str.startswith(('10.', '192.168.')) or
            ip_str.startswith(('172.16.', '172.17.', '172.18.', '172.19.', 
                            '172.20.', '172.21.', '172.22.', '172.23.',
                            '172.24.', '172.25.', '172.26.', '172.27.',
                            '172.28.', '172.29.', '172.30.', '172.31.')) or
            ip_str.startswith('fd00:')  # IPv6 ULA (RFC 4193)
        )
    
    def _gen_ip_asn(self):
        if not self.data.get('ip_asn'):
            return "\\section{IP/ASN}\nDados não disponíveis.\n"
        
        latex_output = []
        for entry in self.data['ip_asn']:
            # Extrai dados básicos
            ip = entry.get('ip', 'N/A')
            asn = entry.get('asn', 'N/A')
            asn_cidr = entry.get('asn_cidr', 'N/A')
            network = entry.get('network', {})
            
            if self.is_private_ip(ip):
                table = f"""
\\subsection{{IP: {ip} - ALERTA: IP Privado Exposto}}
\\begin{{tabular}}{{|l|l|}}
\\hline
\\textbf{{IP}} & \\textbf{{\\textcolor{{red}}{{ {ip} }} }} \\\\ \\hline
\\textbf{{Risco}} & \\textbf{{\\textcolor{{red}}{{Crítico}}}} \\\\ \\hline
\\textbf{{Recomendação}} & Remover imediatamente do DNS/ASN. \\\\ \\hline
\\end{{tabular}}

\\subsection*{{Ações Imediatas}}
\\begin{{itemize}}
\\item Verificar registros DNS (A, PTR) e firewalls.
\\item Auditar dispositivos na rede interna usando este IP.
\\item Implementar \\texttt{{NAT}} ou filtros de borda.
\\end{{itemize}}
"""
            else:
            # Construção da tabela principal
                table = f"""
    \\subsection{{IP: {ip}}}
    \\begin{{tabular}}{{|l|l|}}
    \\hline
    \\textbf{{ASN}} & {asn} ({network.get('name', 'N/A')}) \\\\ \\hline
    \\textbf{{Bloco CIDR}} & {asn_cidr} \\\\ \\hline
    \\textbf{{Tipo de Alocação}} & {network.get('type', 'N/A')} \\\\ \\hline
    \\textbf{{Faixa de IPs}} & {network.get('start_address', 'N/A')} - {network.get('end_address', 'N/A')} \\\\ \\hline
    \\textbf{{Registro}} & {entry.get('asn_registry', 'N/A').upper()} (Desde: {entry.get('asn_date', 'N/A')}) \\\\ \\hline
        """

                # Adiciona contatos de rede (se existirem)
                contacts = []
                if 'objects' in entry:
                    for obj_id, obj_data in entry['objects'].items():
                        if 'contact' in obj_data:
                            contact = obj_data['contact']
                            contacts.append(
                                f"\\textbf{{{obj_id}}}: {contact.get('name', 'N/A')} "
                                #f"(Email: \\texttt{{{contact.get('email', ['N/A'])[0]}}})"
                            )
                            break
                
                if contacts:
                    table += "\n\\textbf{Contatos de Rede} & " + "\n".join(contacts) + "\n\\\\ \\hline\n"
                
                table += "\\end{tabular}\n"
            
            latex_output.append(table)
        
        return "\\section{IP e ASN}\n" + "\n".join(latex_output)

    def _gen_whois(self):
        if not self.data['whois']:
            return "\\section{WHOIS}\nDados não disponíveis.\n"
        
        w = self.data['whois']
        return f"""
\\section{{WHOIS}}
\\begin{{tabular}}{{|l|l|}}
\\hline
\\textbf{{Domínio}} & {self.domain} \\\\ \\hline
\\textbf{{Registrante}} & {w.get('registrant_name', 'N/A')} \\\\ \\hline
\\textbf{{CNPJ}} & {w.get('registrant_id', 'N/A')} \\\\ \\hline
\\textbf{{Email}} & \\texttt{{{w.get('email', 'N/A')}}} \\\\ \\hline
\\textbf{{Nameservers}} & {', '.join(w.get('name_server', []))} \\\\ \\hline
\\textbf{{Criação}} & {w.get('creation_date', ['N/A'])[0]} \\\\ \\hline
\\textbf{{Expiração}} & {w.get('expiration_date', 'N/A')} \\\\ \\hline
\\end{{tabular}}
"""

    def _gen_dns(self):
        if not self.data['dns']:
            return "\\section{DNS}\nDados não disponíveis.\n"
        
        rows = []
        for record_type, values in self.data['dns'].items():
            rows.append(f"{record_type} & {', '.join(values)} \\\\ \\hline")
        
        return f"""
\\section{{DNS Enumeration}}
\\begin{{tabularx}}{{\\textwidth}}{{|l|X|}}
\\hline
{"\n".join(rows)}
\\end{{tabularx}}
"""

    def _analyze_spf(self):
        if not self.data.get('dns') or 'TXT' not in self.data['dns']:
            return None
        
        spf_records = [txt for txt in self.data['dns']['TXT'] if 'v=spf1' in txt]
        if not spf_records:
            return {
                'status': 'Ausente',
                'risk': 'Alto',
                'details': 'Nenhum registro SPF encontrado.'
            }
        
        spf = spf_records[0]
        issues = []
        
        # Verifica mecanismos essenciais
        if 'all' not in spf:
            issues.append("Falta mecanismo 'all' (~all ou -all)")
        if 'include:' not in spf and 'ip4:' not in spf:
            issues.append("Falta mecanismos de inclusão (include/ip4)")
        
        return {
            'status': 'Incompleto' if issues else 'Válido',
            'risk': 'Médio' if issues else 'Baixo',
            'details': issues if issues else None,
            'record': spf
        }

    def _gen_spf_analysis(self):
        spf_data = self._analyze_spf()
        if not spf_data:
            return "\\section{SPF}\nDados não disponíveis.\n"
        
        return f"""
    \\section{{Análise de SPF}}
    \\begin{{tabularx}}{{\\textwidth}}{{|l|X|}}
    \\hline
    \\textbf{{Status}} & {spf_data['status']} \\\\ \\hline
    \\textbf{{Risco}} & {spf_data['risk']} \\\\ \\hline
    \\textbf{{Registro}} & \\texttt{{{spf_data.get('record', 'N/A')}}} \\\\ \\hline
    \\end{{tabularx}}

    \\subsection*{{Problemas Identificados}}
    {"Nenhum." if not spf_data['details'] else "\\begin{itemize}\\item " + "\\item ".join(spf_data['details']) + "\\end{itemize}"}
    """    

    def _gen_geo(self):
        if not self.data['geo']:
            return "\\section{Geolocalização}\nDados não disponíveis.\n"
        
        geo_items = []
        for loc in self.data['geo']:
            geo_items.append(
                f"\\item \\textbf{{{loc['query']}}}: {loc['city']}, {loc['country']} "
                f"(AS: {loc['as']})"
            )
        return f"""
\\section{{Geolocalização}}
\\begin{{itemize}}
{"".join(geo_items)}
\\end{{itemize}}
"""

    def _gen_subdomains(self):
        if not self.data['subdomains']:
            return "\\section{Subdomínios}\nNenhum subdomínio encontrado.\n"
        
        return f"""
\\section{{Subdomínios}}
\\begin{{multicols}}{{2}}  % Inicia duas colunas
\\begin{{itemize}}
{"".join([f"\\item \\texttt{{{sub}}}" for sub in self.data['subdomains']])}
\\end{{itemize}}
\\end{{multicols}}
"""

if __name__ == "__main__":
    #domain = "directcall.com.br"
    parser = argparse.ArgumentParser(description="Automatiza a criação de relatórios.")
    parser.add_argument("--dominio", required=True, help="Domínio dominio1.com")
    parser.add_argument("--modulo", default="all", choices=['foot', 'finger', 'all'], help="Módulo a ser executado: foot (Footprint), finger (Fingerprint) ou all (Ambos). Padrão: all")
    parser.add_argument("--output_dir", default="output/report", help="Diretório base para salvar os resultados. Padrão: output")

    args = parser.parse_args()


    reporter = FootprintReporter(args.dominio, args.output_dir)
    
    reporter.load_data(
        whois=f"output/{args.dominio}/footprint/whois.txt",
        dns=f"output/{args.dominio}/footprint/dns_enumeration.json",
        geo=f"output/{args.dominio}/footprint/geolocation.json",
        subdomains=f"output/{args.dominio}/footprint/all_subdomains.txt",
        ip_asn=f"output/{args.dominio}/footprint/ip_asn.json"
    )
    
    for section in ['whois', 'dns', 'spf', 'geo', 'subdomains', 'ip_asn']:
        reporter.generate_section(section)
    
    print(f"Relatórios gerados em: output/{reporter.output_dir}/")
