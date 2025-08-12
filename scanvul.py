import socket
import datetime
import nvdlib
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.colors import red, orange, green, black, blue, purple
from reportlab.lib.units import cm
from reportlab.lib.utils import ImageReader
from reportlab.platypus import Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
import argparse
import logging
import json
from time import sleep
import re

# Configuração do logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Cache para CPEs e CVEs
CACHE_FILE = 'vuln_cache.json'
vuln_cache = {}

# Carregar cache se existir
try:
    with open(CACHE_FILE, 'r') as f:
        vuln_cache = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    vuln_cache = {'cpes': {}, 'cves': {}}

# Portas comuns para verificação com descrições de risco
COMMON_PORTS = {
    21: ("FTP", "Verificar se está usando SFTP/FTPS e autenticação segura."),
    22: ("SSH", "Verificar versão, desativar root login e usar autenticação por chaves."),
    23: ("Telnet", "Protocolo inseguro, deve ser desativado e substituído por SSH."),
    25: ("SMTP", "Verificar configurações anti-spoofing e usar STARTTLS."),
    53: ("DNS", "Verificar se há DNSSEC e proteção contra DNS amplification attacks."),
    80: ("HTTP", "Redirecionar para HTTPS e desativar versões antigas do TLS."),
    110: ("POP3", "Usar POP3S com TLS e desativar versões antigas."),
    143: ("IMAP", "Usar IMAPS com TLS e desativar autenticação plaintext."),
    443: ("HTTPS", "Verificar certificado, cipher suites e headers de segurança."),
    445: ("SMB", "Desativar SMBv1 e configurar autenticação adequada."),
    465: ("SMTPS", "Verificar certificado e configurações de segurança."),
    587: ("SMTP Submission", "Verificar autenticação e uso de STARTTLS."),
    993: ("IMAPS", "Verificar certificado e configurações de segurança."),
    995: ("POP3S", "Verificar certificado e configurações de segurança."),
    1433: ("MS SQL", "Configurar autenticação segura e limitar acesso."),
    1521: ("Oracle DB", "Configurar autenticação segura e limitar acesso."),
    3306: ("MySQL", "Configurar autenticação segura e limitar acesso."),
    3389: ("RDP", "Habilitar NLA, limitar tentativas de login e usar 2FA se possível."),
    5432: ("PostgreSQL", "Configurar autenticação segura e limitar acesso."),
    5900: ("VNC", "Usar autenticação forte e tunelamento SSH."),
    8080: ("HTTP Alt", "Mesmas recomendações que porta 80."),
    8443: ("HTTPS Alt", "Mesmas recomendações que porta 443."),
}

def save_cache():
    """Salva o cache de vulnerabilidades em arquivo"""
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(vuln_cache, f)
    except Exception as e:
        logger.error(f"Erro ao salvar cache: {e}")

def parse_args():
    """Parseia argumentos da linha de comando"""
    parser = argparse.ArgumentParser(description='Scanner de Rede Avançado com Relatório de Vulnerabilidades')
    parser.add_argument('-n', '--network', required=True, help='Rede no formato CIDR (ex: 192.168.1.0/24)')
    parser.add_argument('-p', '--ports', nargs='+', type=int, default=list(COMMON_PORTS.keys()),
                        help='Portas a serem escaneadas (padrão: portas comuns)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Número de threads para escaneamento')
    parser.add_argument('-l', '--logo', help='Caminho para o logo')
    parser.add_argument('-o', '--output', default='relatorio_seguranca.pdf', help='Nome do arquivo de saída')
    parser.add_argument('-v', '--verbose', action='store_true', help='Modo verboso')
    return parser.parse_args()

def is_host_active(ip, timeout=1):
    """Verifica se um host está ativo usando ping ICMP"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(timeout)
        sock.sendto(b'\x08\x00\xf7\xff\x00\x00\x00\x00', (str(ip), 0))
        sock.recvfrom(1024)
        return True
    except:
        return False
    finally:
        try:
            sock.close()
        except:
            pass

def scan_network(network_cidr):
    """Escaneia a rede e retorna hosts ativos"""
    network = ipaddress.ip_network(network_cidr)
    active_hosts = []
    
    logger.info(f"Escaneando rede {network_cidr} para hosts ativos...")
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(is_host_active, host): host for host in network.hosts()}
        
        for future in as_completed(futures):
            host = futures[future]
            try:
                if future.result():
                    active_hosts.append(str(host))
                    logger.info(f"Host ativo encontrado: {host}")
            except Exception as e:
                logger.error(f"Erro ao verificar host {host}: {e}")
    
    return active_hosts

def grab_banner(ip, port, timeout=2):
    """Tenta obter o banner de um serviço"""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            
            # Tenta ler o banner inicial
            try:
                banner = sock.recv(1024).decode(errors="ignore").strip()
                if banner:
                    return banner
            except:
                pass
            
            # Tenta enviar comandos específicos para serviços conhecidos
            if port == 80 or port == 443 or port == 8080 or port == 8443:
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                return sock.recv(1024).decode(errors="ignore").strip()
            elif port == 21:
                sock.sendall(b"USER anonymous\r\n")
                return sock.recv(1024).decode(errors="ignore").strip()
            elif port == 22:
                return sock.recv(1024).decode(errors="ignore").strip()
            
            return "Banner não identificado"
    except Exception as e:
        logger.debug(f"Erro ao obter banner da porta {port} em {ip}: {e}")
        return f"Erro: {str(e)}"

def get_service_info(port):
    """Retorna informações sobre o serviço da porta"""
    return COMMON_PORTS.get(port, ("Serviço desconhecido", "Risco não especificado"))

def search_cpe(keyword):
    """Busca CPE com base no banner ou nome do serviço"""
    if not keyword:
        return None
    
    # Verifica cache primeiro
    cache_key = keyword.lower()
    if cache_key in vuln_cache['cpes']:
        return vuln_cache['cpes'][cache_key]
    
    try:
        # Limita a 1 requisição por segundo para evitar rate limiting
        sleep(1)
        results = nvdlib.searchCPE(keywordSearch=keyword)
        
        if results:
            cpe = results[0].cpe23Uri
            vuln_cache['cpes'][cache_key] = cpe
            save_cache()
            return cpe
    except Exception as e:
        logger.error(f"Erro ao buscar CPE para {keyword}: {e}")
    
    return None

def search_cves_by_cpe(cpe_uri, max_results=10):
    """Busca CVEs associados a um CPE"""
    if not cpe_uri:
        return []
    
    # Verifica cache primeiro
    if cpe_uri in vuln_cache['cves']:
        return vuln_cache['cves'][cpe_uri]
    
    try:
        # Limita a 1 requisição por segundo para evitar rate limiting
        sleep(1)
        cves = nvdlib.searchCVE(cpeName=cpe_uri)
        
        # Processa e armazena no cache
        processed_cves = []
        for cve in cves[:max_results]:
            try:
                processed_cve = {
                    'id': cve.id,
                    'severity': cve.v31severity if cve.v31severity else "N/A",
                    'score': str(cve.v31score) if cve.v31score else "N/A",
                    'desc': cve.descriptions[0].value if cve.descriptions else "Descrição não disponível",
                    'link': f"https://nvd.nist.gov/vuln/detail/{cve.id}"
                }
                processed_cves.append(processed_cve)
            except Exception as e:
                logger.error(f"Erro ao processar CVE {cve.id}: {e}")
        
        vuln_cache['cves'][cpe_uri] = processed_cves
        save_cache()
        return processed_cves
    except Exception as e:
        logger.error(f"Erro ao buscar CVEs para {cpe_uri}: {e}")
        return []

def extract_software_info(banner):
    """Extrai informações de software do banner"""
    if not banner or "Erro" in banner:
        return None
    
    # Padrões comuns para extração de versões
    patterns = [
        r"(Apache[/\s](\d+\.\d+(\.\d+)?)",
        r"(nginx[/\s](\d+\.\d+(\.\d+)?)",
        r"(OpenSSH[_/](\d+\.\d+(p\d+)?))",
        r"(Microsoft IIS[/\s](\d+\.\d+))",
        r"(ProFTPD[/\s](\d+\.\d+\.\d+))",
        r"(vsFTPd[/\s](\d+\.\d+\.\d+))",
        r"(PostgreSQL[/\s](\d+\.\d+(\.\d+)?))",
        r"(MySQL[/\s](\d+\.\d+\.\d+))"
    ]
    
    for pattern in patterns:
        match = re.search(pattern, banner)
        if match:
            return match.group(1)
    
    return banner.split('\n')[0].strip() if '\n' in banner else banner.strip()

def scan_host(ip, ports):
    """Escaneia um host específico nas portas especificadas"""
    host_data = {
        'ip': ip,
        'ports': [],
        'os_guess': None,
        'hostname': None
    }
    
    logger.info(f"Escaneando host {ip}...")
    
    try:
        # Tentar resolver hostname
        try:
            host_data['hostname'] = socket.gethostbyaddr(ip)[0]
        except:
            pass
        
        # Escanear portas
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            port_futures = {executor.submit(scan_port, ip, port): port for port in ports}
            
            for future in as_completed(port_futures):
                port = port_futures[future]
                try:
                    port_data = future.result()
                    if port_data:
                        host_data['ports'].append(port_data)
                except Exception as e:
                    logger.error(f"Erro ao escanear porta {port} em {ip}: {e}")
    
    except Exception as e:
        logger.error(f"Erro ao escanear host {ip}: {e}")
    
    return host_data

def scan_port(ip, port):
    """Escaneia uma porta específica"""
    port_data = None
    
    try:
        # Verifica se a porta está aberta
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                banner = grab_banner(ip, port)
                service_name, risk_note = get_service_info(port)
                software_info = extract_software_info(banner)
                
                port_data = {
                    'port': port,
                    'status': 'open',
                    'service': service_name,
                    'banner': banner,
                    'software': software_info,
                    'risk_note': risk_note,
                    'cpe': None,
                    'cves': []
                }
                
                # Buscar CPE e CVEs se houver informação de software
                if software_info and not "Erro" in software_info:
                    cpe = search_cpe(software_info)
                    if cpe:
                        port_data['cpe'] = cpe
                        port_data['cves'] = search_cves_by_cpe(cpe)
                
                logger.info(f"Porta {port} aberta em {ip}: {service_name}")
            else:
                port_data = {
                    'port': port,
                    'status': 'closed/filtered',
                    'service': None,
                    'banner': None,
                    'software': None,
                    'risk_note': None,
                    'cpe': None,
                    'cves': []
                }
    except Exception as e:
        logger.error(f"Erro ao escanear porta {port} em {ip}: {e}")
        port_data = {
            'port': port,
            'status': 'error',
            'error': str(e)
        }
    
    return port_data

def generate_pdf(report_data, filename, logo_path=None):
    """Gera o relatório em PDF"""
    pdf = canvas.Canvas(filename, pagesize=A4)
    width, height = A4
    styles = getSampleStyleSheet()
    
    # CAPA
    if logo_path:
        try:
            logo = ImageReader(logo_path)
            pdf.drawImage(logo, (width/2)-2*cm, height-6*cm, 4*cm, 4*cm)
        except Exception as e:
            logger.error(f'Erro ao adicionar logo: {e}')
    
    pdf.setFont("Helvetica-Bold", 22)
    pdf.drawCentredString(width/2, height-8*cm, "Relatório Completo de Segurança")
    pdf.setFont("Helvetica", 14)
    pdf.drawCentredString(width/2, height-9*cm, f"Rede Analisada: {report_data['network']}")
    pdf.drawCentredString(width/2, height-10*cm, f"Data: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M')}")
    pdf.showPage()
    
    # SUMÁRIO EXECUTIVO
    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(2*cm, height-2*cm, "Sumário Executivo")
    
    # Estatísticas
    total_hosts = len(report_data['hosts'])
    open_ports = sum(len(h['ports']) for h in report_data['hosts'])
    vulnerabilities = sum(len(p['cves']) for h in report_data['hosts'] for p in h['ports'] if p['status'] == 'open')
    
    summary_text = [
        f"Total de hosts ativos: {total_hosts}",
        f"Total de portas abertas encontradas: {open_ports}",
        f"Total de vulnerabilidades identificadas: {vulnerabilities}",
        "",
        "Principais riscos identificados:"
    ]
    
    # Adiciona principais vulnerabilidades críticas/altas
    y_pos = height-3.5*cm
    pdf.setFont("Helvetica", 12)
    
    for line in summary_text:
        pdf.drawString(2*cm, y_pos, line)
        y_pos -= 0.7*cm
    
    # Coletar todas as vulnerabilidades críticas/altas
    critical_vulns = []
    for host in report_data['hosts']:
        for port in host['ports']:
            if port['status'] == 'open' and port['cves']:
                for cve in port['cves']:
                    if cve['severity'] in ['CRITICAL', 'HIGH']:
                        critical_vulns.append(f"{cve['id']} ({cve['severity']}) - {host['ip']}:{port['port']}")
    
    # Limita a 10 principais
    for vuln in critical_vulns[:10]:
        pdf.drawString(2.5*cm, y_pos, f"- {vuln}")
        y_pos -= 0.7*cm
    
    pdf.showPage()
    
    # DETALHES POR HOST
    for host in report_data['hosts']:
        if not host['ports']:
            continue
            
        pdf.setFont("Helvetica-Bold", 16)
        pdf.drawString(2*cm, height-2*cm, f"Host: {host['ip']}")
        if host['hostname']:
            pdf.setFont("Helvetica", 12)
            pdf.drawString(2*cm, height-2.5*cm, f"Hostname: {host['hostname']}")
        
        y_pos = height-3.5*cm
        
        # Tabela de portas
        port_data = [['Porta', 'Serviço', 'Status', 'Risco']]
        for port in host['ports']:
            if port['status'] == 'open':
                port_data.append([
                    str(port['port']),
                    port['service'],
                    port['status'],
                    port['risk_note'][:50] + '...' if port['risk_note'] else 'N/A'
                ])
        
        if len(port_data) > 1:
            pdf.setFont("Helvetica-Bold", 14)
            pdf.drawString(2*cm, y_pos, "Portas Abertas:")
            y_pos -= 0.7*cm
            
            table = Table(port_data, colWidths=[2*cm, 4*cm, 3*cm, 7*cm])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), (0.8, 0.8, 0.8)),
                ('TEXTCOLOR', (0, 0), (-1, 0), (0, 0, 0)),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, (0.7, 0.7, 0.7)),
            ]))
            
            table.wrapOn(pdf, width, height)
            table.drawOn(pdf, 2*cm, y_pos-5*cm)
            y_pos -= 5.5*cm + (0.5*cm * len(port_data))
        
        # Detalhes por porta
        pdf.setFont("Helvetica-Bold", 14)
        pdf.drawString(2*cm, y_pos, "Detalhes das Portas Abertas:")
        y_pos -= 0.7*cm
        
        for port in host['ports']:
            if port['status'] != 'open':
                continue
                
            pdf.setFont("Helvetica-Bold", 12)
            pdf.setFillColor(black)
            pdf.drawString(2*cm, y_pos, f"Porta {port['port']} - {port['service']}")
            y_pos -= 0.5*cm
            
            pdf.setFont("Helvetica", 10)
            pdf.drawString(2*cm, y_pos, f"Status: {port['status']}")
            y_pos -= 0.5*cm
            
            if port['banner']:
                banner_text = f"Banner: {port['banner'][:100]}" + ('...' if len(port['banner']) > 100 else '')
                pdf.drawString(2*cm, y_pos, banner_text)
                y_pos -= 0.5*cm
            
            pdf.drawString(2*cm, y_pos, f"Nota de Risco: {port['risk_note']}")
            y_pos -= 0.5*cm
            
            if port['cpe']:
                pdf.drawString(2*cm, y_pos, f"CPE identificado: {port['cpe']}")
                y_pos -= 0.5*cm
            
            # Vulnerabilidades
            if port['cves']:
                pdf.setFont("Helvetica-Bold", 11)
                pdf.drawString(2*cm, y_pos, "Vulnerabilidades Associadas:")
                y_pos -= 0.5*cm
                
                for cve in port['cves']:
                    pdf.setFont("Helvetica-Bold", 10)
                    
                    # Cor baseada na severidade
                    if cve['severity'] == 'CRITICAL':
                        pdf.setFillColor(purple)
                    elif cve['severity'] == 'HIGH':
                        pdf.setFillColor(red)
                    elif cve['severity'] == 'MEDIUM':
                        pdf.setFillColor(orange)
                    elif cve['severity'] == 'LOW':
                        pdf.setFillColor(green)
                    else:
                        pdf.setFillColor(black)
                    
                    pdf.drawString(2.5*cm, y_pos, f"{cve['id']} ({cve['severity']} - {cve['score']})")
                    y_pos -= 0.5*cm
                    
                    pdf.setFillColor(black)
                    pdf.setFont("Helvetica", 9)
                    desc = Paragraph(cve['desc'], styles['Normal'])
                    desc.wrapOn(pdf, width-4*cm, height)
                    desc.drawOn(pdf, 2.5*cm, y_pos-0.7*cm)
                    y_pos -= 1.5*cm
                    
                    pdf.setFillColor(blue)
                    pdf.drawString(2.5*cm, y_pos, cve['link'])
                    y_pos -= 0.7*cm
                    
                    pdf.setFillColor(black)
                    y_pos -= 0.3*cm
            
            pdf.line(2*cm, y_pos, width-2*cm, y_pos)
            y_pos -= 0.7*cm
            
            if y_pos < 3*cm:
                pdf.showPage()
                y_pos = height-2*cm
    
        pdf.showPage()
    
    # CONCLUSÃO E RECOMENDAÇÕES
    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(2*cm, height-2*cm, "Conclusão e Recomendações Gerais")
    
    y_pos = height-3*cm
    pdf.setFont("Helvetica", 12)
    
    recommendations = [
        "1. Priorize a correção das vulnerabilidades críticas e altas identificadas.",
        "2. Desative serviços desnecessários e portas abertas sem uso.",
        "3. Atualize todos os softwares para as versões mais recentes.",
        "4. Implemente políticas de senhas fortes e autenticação multifator.",
        "5. Configure firewalls para restringir acesso apenas a IPs autorizados.",
        "6. Monitore logs regularmente para detectar atividades suspeitas.",
        "7. Considere realizar testes de penetração regulares.",
        "8. Implemente criptografia para todos os serviços que lidam com dados sensíveis.",
        "9. Eduque usuários sobre práticas seguras e phishing.",
        "10. Estabeleça um plano de resposta a incidentes."
    ]
    
    for rec in recommendations:
        pdf.drawString(2*cm, y_pos, rec)
        y_pos -= 0.7*cm
    
    pdf.save()
    logger.info(f"Relatório gerado: {filename}")

def main():
    global args
    args = parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    try:
        # Verifica se a rede é válida
        network = ipaddress.ip_network(args.network)
    except ValueError as e:
        logger.error(f"Rede inválida: {e}")
        return
    
    # Escaneia a rede
    active_hosts = scan_network(args.network)
    
    if not active_hosts:
        logger.error("Nenhum host ativo encontrado na rede.")
        return
    
    # Escaneia cada host ativo
    report_data = {
        'network': args.network,
        'scan_date': datetime.datetime.now().isoformat(),
        'hosts': []
    }
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        host_futures = {executor.submit(scan_host, host, args.ports): host for host in active_hosts}
        
        for future in as_completed(host_futures):
            host = host_futures[future]
            try:
                host_data = future.result()
                if host_data['ports']:
                    report_data['hosts'].append(host_data)
            except Exception as e:
                logger.error(f"Erro ao escanear host {host}: {e}")
    
    # Gera o relatório
    generate_pdf(report_data, args.output, args.logo)
    
    # Salva cache final
    save_cache()

if __name__ == "__main__":
    main()