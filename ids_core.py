"""
SISTEMA IDS INSTITUCIONAL
Descripción: Sistema de Detección de Intrusos (IDS) basado en consola.
Intercepta tráfico de red analizando la Capa 2 (MAC), Capa 3 (IP) y Capa 7 (DNS).
Incluye integración de Threat Intelligence (Whois) y envío de alertas por correo seguro.
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
# Clase para manejar el formato visual en la terminal de Linux
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
# Cargamos las credenciales desde el archivo .env para evitar contraseñas hardcodeadas
load_dotenv()

SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")

# ==========================================
# VARIABLES DE ESTADO Y CACHÉ
# ==========================================
# Sets (conjuntos) para recordar a quién ya reportamos y evitar hacer spam de correos
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

# Inicializamos las listas en memoria al arrancar el script
WHITELIST = cargar_whitelist()
BLACKLIST = cargar_blacklist()

def enviar_alerta(asunto, mensaje_cuerpo):
    """Función centralizada para enviar correos electrónicos mediante SMTP con cifrado TLS."""
    try:
        # Soportar múltiples correos de administradores separados por coma
        destinatarios = [email.strip() for email in ADMIN_EMAIL.split(',')]
        
        # Estructurar el mensaje MIME
        msg = MIMEMultipart()
        msg['From'] = f"Sistema IDS Institucional <{SENDER_EMAIL}>"
        msg['To'] = ", ".join(destinatarios)
        msg['Subject'] = asunto
        msg.attach(MIMEText(mensaje_cuerpo, 'plain'))

        # Iniciar conexión segura, autenticar y enviar
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, destinatarios, msg.as_string())
        server.quit()
        print(f"{Color.GREEN}[+] Correo de alerta enviado exitosamente a {len(destinatarios)} destinatario(s).{Color.RESET}")
    except Exception as e:
        print(f"{Color.RED}[-] Error enviando correo: {e}{Color.RESET}")

def ejecutar_analisis_forense(ip_peligrosa, ip_interna):
    """
    Módulo de Automatización Forense: 
    Hace una consulta Whois/RDAP a la IP maliciosa para extraer los correos de reporte de abuso.
    """
    print(f"{Color.YELLOW}[*] Iniciando análisis automatizado Whois para {ip_peligrosa}...{Color.RESET}")
    try:
        obj = IPWhois(ip_peligrosa)
        resultados = obj.lookup_rdap()
        
        # Extraer el nombre de la organización dueña de la IP
        asn_description = resultados.get('asn_description', 'Desconocido')
        
        # Bucle seguro para extraer correos de la respuesta JSON evitando errores NoneType
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

        # Estructurar la alerta crítica
        asunto = f"ALERTA DE EMERGENCIA: Riesgo Virus/Botnet detectado - IP {ip_peligrosa}"
        cuerpo = (
            "El Sistema IDS Institucional ha detectado una conexión hacia una IP clasificada como PELIGROSA.\n\n"
            "--- DETALLES DEL INCIDENTE ---\n"
            f"IP Origen (Usuario Interno): {ip_interna}\n"
            f"IP Destino (Maliciosa): {ip_peligrosa}\n\n"
            "--- INTELIGENCIA FORENSE (WHOIS) ---\n"
            f"Organización dueña de la IP: {asn_description}\n"
            f"Correos de contacto para reportar abuso: {correos_str}\n\n"
            "Acción recomendada: Aislar el equipo origen y contactar al proveedor de la IP maliciosa."
        )
        enviar_alerta(asunto, cuerpo)
        print(f"{Color.GREEN}[!] Análisis forense completado y enviado al administrador.{Color.RESET}")
    except Exception as e:
        print(f"{Color.RED}[-] Error en el análisis forense: {e}{Color.RESET}")

def procesar_paquete(paquete):
    """
    Función de Callback de Scapy: Se ejecuta por CADA paquete interceptado en la red.
    Aquí reside el núcleo de la lógica del IDS.
    """
    
    # 1. Monitoreo DNS (Capa 7 - Aplicación)
    if paquete.haslayer(DNSQR):
        dominio = paquete[DNSQR].qname.decode('utf-8')
        ip_origen = paquete[IP].src if paquete.haslayer(IP) else "Desconocida"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Registrar en la bitácora física
        with open("sitios_visitados.log", "a") as f:
            f.write(f"[{timestamp}] IP: {ip_origen} solicitó: {dominio}\n")
        print(f"{Color.CYAN}[DNS LOG] {ip_origen} -> {dominio}{Color.RESET}")

    # 2. Threat Intelligence (Monitoreo de conexiones salientes)
    if paquete.haslayer(IP):
        ip_destino = paquete[IP].dst
        ip_origen = paquete[IP].src
        
        # Si la IP destino está en nuestra lista negra, se detona el análisis forense
        if ip_destino in BLACKLIST and ip_destino not in alertas_malware:
            print(f"\n{Color.RED}{Color.BOLD}[!!!] THREAT INTEL: Conexión a IP maliciosa detectada: {ip_destino}{Color.RESET}")
            alertas_malware.add(ip_destino)
            ejecutar_analisis_forense(ip_destino, ip_origen)

    # 3. Listas Blancas de Capa 2 (Enlace de Datos / Direcciones MAC)
    if paquete.haslayer(Ether):
        mac_origen = paquete[Ether].src
        if mac_origen not in WHITELIST.get("macs_permitidas", []) and mac_origen not in alertas_enviadas_mac:
            # Ignorar tráfico broadcast (ff:ff:ff:ff:ff:ff)
            if mac_origen != "ff:ff:ff:ff:ff:ff":
                print(f"{Color.YELLOW}[!] ALERTA CAPA 2: MAC NO AUTORIZADA ({mac_origen}){Color.RESET}")
                enviar_alerta("IDS Alerta: Nueva MAC", f"MAC NO AUTORIZADA: {mac_origen}")
                alertas_enviadas_mac.add(mac_origen)

    # 4. Listas Blancas de Capa 3 (Red / Direcciones IP)
    if paquete.haslayer(IP):
        ip_origen = paquete[IP].src
        # Excluimos la lista negra para no mandar alertas duplicadas
        if ip_origen not in WHITELIST.get("ips_permitidas", []) and ip_origen not in alertas_enviadas_ip and ip_origen not in BLACKLIST:
            print(f"{Color.YELLOW}[!] ALERTA CAPA 3: IP NO AUTORIZADA ({ip_origen}){Color.RESET}")
            enviar_alerta("IDS Alerta: Nueva IP", f"IP NO AUTORIZADA: {ip_origen}")
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
                # Inicia la captura con Scapy. store=False evita que se llene la RAM
                sniff(prn=procesar_paquete, store=False)
            except KeyboardInterrupt:
                # Capturamos la interrupción del teclado (Ctrl+C) para volver al menú limpiamente
                print(f"\n{Color.RED}[!] Motor IDS detenido por el administrador.{Color.RESET}")
                input(f"{Color.CYAN}Presiona Enter para volver al menú...{Color.RESET}")
                
        elif opcion == '2':
            os.system('nano whitelist.json')
            WHITELIST = cargar_whitelist() # Actualización en caliente
            print(f"{Color.GREEN}[+] Lista Blanca recargada en memoria.{Color.RESET}")
            
        elif opcion == '3':
            os.system('nano blacklist.txt')
            BLACKLIST = cargar_blacklist() # Actualización en caliente
            print(f"{Color.GREEN}[+] Lista Negra recargada en memoria.{Color.RESET}")
            
        elif opcion == '4':
            os.system('clear')
            print(f"{Color.BOLD}{Color.CYAN}--- ÚLTIMOS 20 REGISTROS DE NAVEGACIÓN DNS ---{Color.RESET}")
            os.system('tail -n 20 sitios_visitados.log')
            print(f"{Color.BOLD}{Color.CYAN}----------------------------------------------{Color.RESET}")
            input(f"\n{Color.YELLOW}Presiona Enter para volver al menú...{Color.RESET}")
            
        elif opcion == '5':
            os.system('nano .env')
            # Forzar la recarga de las variables desde el archivo .env actualizado
            load_dotenv(override=True)
            SMTP_SERVER = os.getenv("SMTP_SERVER")
            SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
            SENDER_EMAIL = os.getenv("SENDER_EMAIL")
            SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
            ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
            print(f"{Color.GREEN}[+] Archivo .env actualizado. Credenciales de correo recargadas.{Color.RESET}")
            input(f"\n{Color.YELLOW}Presiona Enter para continuar...{Color.RESET}")
            
        elif opcion == '6':
            print(f"\n{Color.RED}Apagando Sistema IDS Institucional. ¡Hasta pronto!{Color.RESET}\n")
            break
            
        else:
            input(f"\n{Color.RED}Opción no válida. Presiona Enter para intentar de nuevo...{Color.RESET}")

if __name__ == "__main__":
    mostrar_menu()