"""
SISTEMA IDS INSTITUCIONAL
Descripción: Sistema de Detección de Intrusos (IDS) basado en consola.
Intercepta tráfico de red analizando la Capa 2 (MAC), Capa 3 (IP) y Capa 7 (DNS).
Incluye integración de Threat Intelligence (Whois) y envío de alertas por correo en formato HTML.
"""

import os
import json
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Librerías de red y forenses
from scapy.all import sniff, IP, Ether, DNSQR
from ipwhois import IPWhois

# ==========================================
# CONFIGURACIÓN DE INTERFAZ Y COLORES ANSI
# ==========================================
class Color:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

# ==========================================
# CARGA DE VARIABLES DE ENTORNO (SEGURIDAD)
# ==========================================
load_dotenv()

SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")

# ==========================================
# VARIABLES DE ESTADO Y CACHÉ
# ==========================================
alertas_enviadas_ip = set()
alertas_enviadas_mac = set()
alertas_malware = set()

def cargar_whitelist():
    """Lee el archivo JSON que contiene las IPs y MACs autorizadas (Capa 2 y 3)."""
    try:
        with open("whitelist.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"ips_permitidas": [], "macs_permitidas": []}

def cargar_blacklist():
    """Lee el archivo de texto con las IPs asociadas a Malware/Botnets."""
    try:
        with open("blacklist.txt", "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return []

WHITELIST = cargar_whitelist()
BLACKLIST = cargar_blacklist()

def enviar_alerta(asunto, mensaje_html):
    """Función centralizada para enviar correos electrónicos en formato HTML."""
    try:
        destinatarios = [email.strip() for email in ADMIN_EMAIL.split(',')]
        
        msg = MIMEMultipart()
        msg['From'] = f"Sistema IDS Institucional <{SENDER_EMAIL}>"
        msg['To'] = ", ".join(destinatarios)
        msg['Subject'] = asunto
        
        # Inyectar el formato HTML
        msg.attach(MIMEText(mensaje_html, 'html'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, destinatarios, msg.as_string())
        server.quit()
        print(f"{Color.GREEN}[+] Correo de alerta (HTML) enviado exitosamente a {len(destinatarios)} destinatario(s).{Color.RESET}")
    except Exception as e:
        print(f"{Color.RED}[-] Error enviando correo: {e}{Color.RESET}")

def ejecutar_analisis_forense(ip_peligrosa, ip_interna):
    """Módulo de Automatización Forense con diseño de correo HTML Crítico."""
    print(f"{Color.YELLOW}[*] Iniciando análisis automatizado Whois para {ip_peligrosa}...{Color.RESET}")
    try:
        obj = IPWhois(ip_peligrosa)
        resultados = obj.lookup_rdap()
        
        asn_description = resultados.get('asn_description', 'Desconocido')
        entidades = resultados.get('objects')
        contactos_abuso = []
        
        if entidades:
            for ent in entidades.values():
                if not ent: continue
                contactos = ent.get('contact')
                if contactos and contactos.get('email'):
                    emails = contactos['email']
                    if isinstance(emails, list):
                        for email in emails:
                            if email and isinstance(email, dict) and email.get('value'):
                                contactos_abuso.append(email['value'])
                    elif isinstance(emails, dict) and emails.get('value'):
                        contactos_abuso.append(emails['value'])
        
        correos_str = ", ".join(set(contactos_abuso)) if contactos_abuso else "No listado públicamente"

        asunto = f"🚨 EMERGENCIA CRÍTICA: Riesgo Botnet detectado - IP {ip_peligrosa}"
        
        # Plantilla HTML en Rojo para Emergencias
        cuerpo_html = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; border: 1px solid #fca5a5; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <div style="background-color: #dc2626; color: white; padding: 15px; text-align: center;">
                <h2 style="margin: 0; font-size: 22px;">🚨 ALERTA DE SEGURIDAD CRÍTICA 🚨</h2>
                <p style="margin: 5px 0 0 0; font-size: 14px;">Conexión a Threat Intelligence (Lista Negra)</p>
            </div>
            <div style="padding: 20px; background-color: #fef2f2; color: #1f2937;">
                <p>El <strong>Sistema IDS Institucional</strong> ha detectado tráfico hacia una IP clasificada como de ALTO RIESGO.</p>
                
                <h3 style="border-bottom: 2px solid #f87171; color: #991b1b; padding-bottom: 5px;">Detalles del Incidente</h3>
                <table style="width: 100%; border-collapse: collapse;">
                    <tr><td style="padding: 8px; border-bottom: 1px solid #fecaca; width: 40%;"><strong>IP Origen (Interna):</strong></td><td style="padding: 8px; border-bottom: 1px solid #fecaca; color: #d97706; font-weight: bold;">{ip_interna}</td></tr>
                    <tr><td style="padding: 8px; border-bottom: 1px solid #fecaca;"><strong>IP Destino (Maliciosa):</strong></td><td style="padding: 8px; border-bottom: 1px solid #fecaca; color: #dc2626; font-weight: bold;">{ip_peligrosa}</td></tr>
                </table>

                <h3 style="border-bottom: 2px solid #f87171; color: #991b1b; padding-bottom: 5px; margin-top: 20px;">Inteligencia Forense (Whois)</h3>
                <table style="width: 100%; border-collapse: collapse;">
                    <tr><td style="padding: 8px; border-bottom: 1px solid #fecaca; width: 40%;"><strong>Organización Dueña:</strong></td><td style="padding: 8px; border-bottom: 1px solid #fecaca;">{asn_description}</td></tr>
                    <tr><td style="padding: 8px; border-bottom: 1px solid #fecaca;"><strong>Contacto de Abuso:</strong></td><td style="padding: 8px; border-bottom: 1px solid #fecaca;">{correos_str}</td></tr>
                </table>
                
                <div style="margin-top: 25px; padding: 15px; background-color: #fee2e2; border-left: 4px solid #b91c1c;">
                    <strong>Acción Recomendada:</strong> Aislar inmediatamente el equipo origen ({ip_interna}) de la red corporativa.
                </div>
            </div>
        </div>
        """
        enviar_alerta(asunto, cuerpo_html)
        print(f"{Color.GREEN}[!] Análisis forense completado y enviado al administrador.{Color.RESET}")
    except Exception as e:
        print(f"{Color.RED}[-] Error en el análisis forense: {e}{Color.RESET}")

def procesar_paquete(paquete):
    """Función de Callback de Scapy: Se ejecuta por CADA paquete interceptado."""
    
    # 1. Monitoreo DNS (Capa 7)
    if paquete.haslayer(DNSQR):
        dominio = paquete[DNSQR].qname.decode('utf-8')
        ip_origen = paquete[IP].src if paquete.haslayer(IP) else "Desconocida"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open("sitios_visitados.log", "a") as f:
            f.write(f"[{timestamp}] IP: {ip_origen} solicitó: {dominio}\n")
        print(f"{Color.CYAN}[DNS LOG] {ip_origen} -> {dominio}{Color.RESET}")

    # 2. Threat Intelligence (Conexiones salientes)
    if paquete.haslayer(IP):
        ip_destino = paquete[IP].dst
        ip_origen = paquete[IP].src
        
        if ip_destino in BLACKLIST and ip_destino not in alertas_malware:
            print(f"\n{Color.RED}{Color.BOLD}[!!!] THREAT INTEL: Conexión a IP maliciosa detectada: {ip_destino}{Color.RESET}")
            alertas_malware.add(ip_destino)
            ejecutar_analisis_forense(ip_destino, ip_origen)

    # 3. Listas Blancas de Capa 2 (Direcciones MAC)
    if paquete.haslayer(Ether):
        mac_origen = paquete[Ether].src
        if mac_origen not in WHITELIST.get("macs_permitidas", []) and mac_origen not in alertas_enviadas_mac:
            if mac_origen != "ff:ff:ff:ff:ff:ff":
                print(f"{Color.YELLOW}[!] ALERTA CAPA 2: MAC NO AUTORIZADA ({mac_origen}){Color.RESET}")
                
                html_mac = f"""
                <div style="font-family: Arial, sans-serif; max-width: 600px; border: 1px solid #fcd34d; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
                    <div style="background-color: #f59e0b; color: white; padding: 10px 15px;">
                        <h2 style="margin: 0; font-size: 18px;">⚠️ ADVERTENCIA: Dispositivo Desconocido</h2>
                    </div>
                    <div style="padding: 15px; background-color: #fffbeb; color: #374151;">
                        <p>Se ha conectado hardware no registrado en la Lista Blanca (Capa 2).</p>
                        <p style="font-size: 16px;"><strong>Dirección MAC:</strong> <span style="color: #b45309; font-family: monospace;">{mac_origen}</span></p>
                    </div>
                </div>
                """
                enviar_alerta("⚠️ IDS Alerta: Nueva MAC Detectada", html_mac)
                alertas_enviadas_mac.add(mac_origen)

    # 4. Listas Blancas de Capa 3 (Direcciones IP)
    if paquete.haslayer(IP):
        ip_origen = paquete[IP].src
        if ip_origen not in WHITELIST.get("ips_permitidas", []) and ip_origen not in alertas_enviadas_ip and ip_origen not in BLACKLIST:
            print(f"{Color.YELLOW}[!] ALERTA CAPA 3: IP NO AUTORIZADA ({ip_origen}){Color.RESET}")
            
            html_ip = f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; border: 1px solid #fcd34d; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
                <div style="background-color: #f59e0b; color: white; padding: 10px 15px;">
                    <h2 style="margin: 0; font-size: 18px;">⚠️ ADVERTENCIA: IP No Autorizada</h2>
                </div>
                <div style="padding: 15px; background-color: #fffbeb; color: #374151;">
                    <p>Se detectó tráfico de una IP no registrada en la Lista Blanca (Capa 3).</p>
                    <p style="font-size: 16px;"><strong>Dirección IP:</strong> <span style="color: #b45309; font-family: monospace;">{ip_origen}</span></p>
                </div>
            </div>
            """
            enviar_alerta("⚠️ IDS Alerta: Nueva IP Detectada", html_ip)
            alertas_enviadas_ip.add(ip_origen)

def mostrar_menu():
    """Despliega la interfaz interactiva principal para el control del sistema."""
    global WHITELIST, BLACKLIST, SMTP_SERVER, SMTP_PORT, SENDER_EMAIL, SENDER_PASSWORD, ADMIN_EMAIL
    
    while True:
        os.system('clear')
        print(f"{Color.CYAN}{Color.BOLD}")
        print(r"""
      _____ _____   _____ 
     |_   _|  __ \ / ____|
       | | | |  | | (___  
       | | | |  | |\___ \ 
      _| |_| |__| |____) |
     |_____|_____/|_____/ 
     --- INSTITUCIONAL ---
        """)
        print(f"{Color.RESET}")
        print(f"{Color.YELLOW}╔═══════════════════════════════════════════════════╗{Color.RESET}")
        print(f"{Color.YELLOW}║{Color.RESET} {Color.BOLD}Panel de Control Principal{Color.RESET}                        {Color.YELLOW}║{Color.RESET}")
        print(f"{Color.YELLOW}╠═══════════════════════════════════════════════════╣{Color.RESET}")
        print(f"{Color.YELLOW}║{Color.RESET} {Color.GREEN}[1]{Color.RESET} Iniciar Motor de Monitoreo (IDS)              {Color.YELLOW}║{Color.RESET}")
        print(f"{Color.YELLOW}║{Color.RESET} {Color.GREEN}[2]{Color.RESET} Ver / Editar Lista Blanca (Capa 2 y 3)        {Color.YELLOW}║{Color.RESET}")
        print(f"{Color.YELLOW}║{Color.RESET} {Color.GREEN}[3]{Color.RESET} Ver / Editar Lista Negra (Threat Intel)       {Color.YELLOW}║{Color.RESET}")
        print(f"{Color.YELLOW}║{Color.RESET} {Color.GREEN}[4]{Color.RESET} Ver Bitácora de Tráfico DNS                   {Color.YELLOW}║{Color.RESET}")
        print(f"{Color.YELLOW}║{Color.RESET} {Color.GREEN}[5]{Color.RESET} Editar Correos de Alerta (.env)               {Color.YELLOW}║{Color.RESET}")
        print(f"{Color.YELLOW}║{Color.RESET} {Color.RED}[6]{Color.RESET} Salir del Sistema                             {Color.YELLOW}║{Color.RESET}")
        print(f"{Color.YELLOW}╚═══════════════════════════════════════════════════╝{Color.RESET}")
        
        opcion = input(f"\n{Color.CYAN}root@ids-institucional:~# {Color.RESET}")
        
        if opcion == '1':
            print(f"\n{Color.GREEN}[*] Iniciando Motor IDS...{Color.RESET}")
            print(f"{Color.GREEN}[*] Módulos L2/L3, DNS y Forense: ACTIVOS{Color.RESET}")
            print(f"{Color.YELLOW}[*] Escuchando red (Presiona Ctrl+C para detener)...{Color.RESET}\n")
            try:
                sniff(prn=procesar_paquete, store=False)
            except KeyboardInterrupt:
                print(f"\n{Color.RED}[!] Motor IDS detenido por el administrador.{Color.RESET}")
                input(f"{Color.CYAN}Presiona Enter para volver al menú...{Color.RESET}")
                
        elif opcion == '2':
            os.system('nano whitelist.json')
            WHITELIST = cargar_whitelist()
            print(f"{Color.GREEN}[+] Lista Blanca recargada en memoria.{Color.RESET}")
            
        elif opcion == '3':
            os.system('nano blacklist.txt')
            BLACKLIST = cargar_blacklist()
            print(f"{Color.GREEN}[+] Lista Negra recargada en memoria.{Color.RESET}")
            
        elif opcion == '4':
            os.system('clear')
            print(f"{Color.BOLD}{Color.CYAN}--- ÚLTIMOS 20 REGISTROS DE NAVEGACIÓN DNS ---{Color.RESET}")
            os.system('tail -n 20 sitios_visitados.log')
            print(f"{Color.BOLD}{Color.CYAN}----------------------------------------------{Color.RESET}")
            input(f"\n{Color.YELLOW}Presiona Enter para volver al menú...{Color.RESET}")
            
        elif opcion == '5':
            os.system('nano .env')
            load_dotenv(override=True)
            SMTP_SERVER = os.getenv("SMTP_SERVER")
            SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
            SENDER_EMAIL = os.getenv("SENDER_EMAIL")
            SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
            ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
            print(f"{Color.GREEN}[+] Archivo .env actualizado. Credenciales recargadas.{Color.RESET}")
            input(f"\n{Color.YELLOW}Presiona Enter para continuar...{Color.RESET}")
            
        elif opcion == '6':
            print(f"\n{Color.RED}Apagando Sistema IDS Institucional. ¡Hasta pronto!{Color.RESET}\n")
            break
            
        else:
            input(f"\n{Color.RED}Opción no válida. Presiona Enter para intentar de nuevo...{Color.RESET}")

if __name__ == "__main__":
    mostrar_menu()