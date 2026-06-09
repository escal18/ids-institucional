"""
SISTEMA IDS INSTITUCIONAL (Versión GUI)
Descripción: Sistema de Detección de Intrusos (IDS) con Interfaz Gráfica.
Intercepta tráfico de red analizando la Capa 2 (MAC), Capa 3 (IP) y Capa 7 (DNS).
Incluye integración de Threat Intelligence (Whois) y envío de alertas por correo en formato HTML.
"""

import os
import sys
import re
import json
import smtplib
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

from scapy.all import sniff, IP, Ether, DNSQR
from ipwhois import IPWhois

# [Índice 1]
class Color:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

# [Índice 2]
load_dotenv()
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")

# [Índice 3]
alertas_enviadas_ip = set()
alertas_enviadas_mac = set()
alertas_malware = set()
ids_corriendo = False

# [Índice 4]
def cargar_whitelist():
    try:
        with open("whitelist.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"ips_permitidas": [], "macs_permitidas": []}

# [Índice 5]
def cargar_blacklist():
    try:
        with open("blacklist.txt", "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return []

WHITELIST = cargar_whitelist()
BLACKLIST = cargar_blacklist()

# [Índice 6]
def enviar_alerta(asunto, mensaje_html):
    try:
        destinatarios = [email.strip() for email in ADMIN_EMAIL.split(',')]
        msg = MIMEMultipart()
        msg['From'] = f"Sistema IDS Institucional <{SENDER_EMAIL}>"
        msg['To'] = ", ".join(destinatarios)
        msg['Subject'] = asunto
        msg.attach(MIMEText(mensaje_html, 'html'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, destinatarios, msg.as_string())
        server.quit()
        print(f"{Color.GREEN}[+] Correo de alerta (HTML) enviado a {len(destinatarios)} destinatario(s).{Color.RESET}")
    except Exception as e:
        print(f"{Color.RED}[-] Error enviando correo: {e}{Color.RESET}")

# [Índice 7]
def ejecutar_analisis_forense(ip_peligrosa, ip_interna):
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
        print(f"{Color.GREEN}[!] Análisis forense completado.{Color.RESET}")
    except Exception as e:
        print(f"{Color.RED}[-] Error forense: {e}{Color.RESET}")

# [Índice 8]
def procesar_paquete(paquete):
    if paquete.haslayer(DNSQR):
        dominio = paquete[DNSQR].qname.decode('utf-8')
        ip_origen = paquete[IP].src if paquete.haslayer(IP) else "Desconocida"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open("sitios_visitados.log", "a") as f:
            f.write(f"[{timestamp}] IP: {ip_origen} solicitó: {dominio}\n")
        print(f"{Color.CYAN}[DNS LOG] {ip_origen} -> {dominio}{Color.RESET}")

    if paquete.haslayer(IP):
        ip_destino = paquete[IP].dst
        ip_origen = paquete[IP].src
        if ip_destino in BLACKLIST and ip_destino not in alertas_malware:
            print(f"\n{Color.RED}{Color.BOLD}[!!!] THREAT INTEL: Conexión a IP maliciosa: {ip_destino}{Color.RESET}")
            alertas_malware.add(ip_destino)
            threading.Thread(target=ejecutar_analisis_forense, args=(ip_destino, ip_origen), daemon=True).start()

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
                threading.Thread(target=enviar_alerta, args=("⚠️ IDS Alerta: Nueva MAC Detectada", html_mac), daemon=True).start()
                alertas_enviadas_mac.add(mac_origen)

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
            threading.Thread(target=enviar_alerta, args=("⚠️ IDS Alerta: Nueva IP Detectada", html_ip), daemon=True).start()
            alertas_enviadas_ip.add(ip_origen)

# [Índice 9]
class RedireccionadorConsola:
    def __init__(self, widget_texto):
        self.widget_texto = widget_texto

    def write(self, mensaje):
        mensaje_limpio = ansi_escape.sub('', mensaje)
        self.widget_texto.insert(tk.END, mensaje_limpio)
        self.widget_texto.see(tk.END)

    def flush(self):
        pass

# [Índice 10]
class AplicacionIDS:
    def __init__(self, root):
        self.root = root
        self.root.title("Sistema IDS Institucional - Panel de Control")
        self.root.geometry("900x600")
        self.root.configure(bg="#1e1e1e")

        titulo = tk.Label(root, text="🛡️ SISTEMA IDS INSTITUCIONAL", font=("Helvetica", 16, "bold"), bg="#005f73", fg="white", pady=10)
        titulo.pack(fill=tk.X)

        main_frame = tk.Frame(root, bg="#1e1e1e")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        panel_botones = tk.Frame(main_frame, bg="#2d2d2d", width=250)
        panel_botones.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))

        self.consola = scrolledtext.ScrolledText(main_frame, bg="#0d1117", fg="#00ff00", font=("Consolas", 10))
        self.consola.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        sys.stdout = RedireccionadorConsola(self.consola)
        sys.stderr = RedireccionadorConsola(self.consola)

        self.btn_iniciar = tk.Button(panel_botones, text="▶ Iniciar Monitoreo IDS", bg="#2a9d8f", fg="white", font=("Arial", 11, "bold"), command=self.iniciar_ids)
        self.btn_iniciar.pack(fill=tk.X, padx=10, pady=15)

        self.btn_detener = tk.Button(panel_botones, text="⏹ Detener Monitoreo", bg="#e76f51", fg="white", font=("Arial", 11, "bold"), command=self.detener_ids, state=tk.DISABLED)
        self.btn_detener.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(panel_botones, text="Configuración:", bg="#2d2d2d", fg="white", font=("Arial", 10, "bold")).pack(pady=(20, 5))

        tk.Button(panel_botones, text="📝 Editar Lista Blanca", command=lambda: self.abrir_editor("whitelist.json")).pack(fill=tk.X, padx=10, pady=5)
        tk.Button(panel_botones, text="📝 Editar Lista Negra", command=lambda: self.abrir_editor("blacklist.txt")).pack(fill=tk.X, padx=10, pady=5)
        tk.Button(panel_botones, text="📧 Editar Correos (.env)", command=lambda: self.abrir_editor(".env")).pack(fill=tk.X, padx=10, pady=5)
        
        tk.Button(panel_botones, text="📄 Ver Logs DNS", bg="#457b9d", fg="white", command=self.ver_logs).pack(fill=tk.X, padx=10, pady=25)

        print("[*] Sistema Inicializado. Listo para operar.")

    # [Índice 11]
    def iniciar_ids(self):
        global ids_corriendo
        ids_corriendo = True
        self.btn_iniciar.config(state=tk.DISABLED)
        self.btn_detener.config(state=tk.NORMAL)
        print("\n[*] Iniciando Motor IDS...")
        print("[*] Escuchando red (Modo Interfaz Gráfica)...")
        
        self.hilo_sniff = threading.Thread(target=self.hilo_scapy)
        self.hilo_sniff.daemon = True
        self.hilo_sniff.start()

    # [Índice 12]
    def detener_ids(self):
        global ids_corriendo
        ids_corriendo = False
        self.btn_iniciar.config(state=tk.NORMAL)
        self.btn_detener.config(state=tk.DISABLED)
        print("[!] Motor IDS detenido por el administrador.")

    # [Índice 13]
    def hilo_scapy(self):
        sniff(prn=procesar_paquete, store=False, stop_filter=lambda x: not ids_corriendo)

    # [Índice 14]
    def abrir_editor(self, archivo):
        if not os.path.exists(archivo):
            open(archivo, 'w').close()
            
        ventana_editor = tk.Toplevel(self.root)
        ventana_editor.title(f"Editando: {archivo}")
        ventana_editor.geometry("600x400")

        texto = scrolledtext.ScrolledText(ventana_editor, font=("Consolas", 11))
        texto.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        with open(archivo, "r") as f:
            texto.insert(tk.END, f.read())

        def guardar():
            with open(archivo, "w") as f:
                f.write(texto.get("1.0", tk.END).strip())
            
            global WHITELIST, BLACKLIST, SMTP_SERVER, SMTP_PORT, SENDER_EMAIL, SENDER_PASSWORD, ADMIN_EMAIL
            if archivo == "whitelist.json":
                WHITELIST = cargar_whitelist()
            elif archivo == "blacklist.txt":
                BLACKLIST = cargar_blacklist()
            elif archivo == ".env":
                load_dotenv(override=True)
                SMTP_SERVER = os.getenv("SMTP_SERVER")
                SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
                SENDER_EMAIL = os.getenv("SENDER_EMAIL")
                SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
                ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
                
            print(f"[+] Archivo {archivo} guardado y recargado en memoria.")
            ventana_editor.destroy()

        tk.Button(ventana_editor, text="Guardar Cambios", bg="#2a9d8f", fg="white", font=("Arial", 10, "bold"), command=guardar).pack(pady=10)

    # [Índice 15]
    def ver_logs(self):
        try:
            with open("sitios_visitados.log", "r") as f:
                lineas = f.readlines()[-20:]
            
            ventana_logs = tk.Toplevel(self.root)
            ventana_logs.title("Últimos 20 Registros DNS")
            ventana_logs.geometry("700x300")
            
            texto = scrolledtext.ScrolledText(ventana_logs, bg="black", fg="#00ff00", font=("Consolas", 10))
            texto.pack(fill=tk.BOTH, expand=True)
            texto.insert(tk.END, "".join(lineas))
            texto.config(state=tk.DISABLED)
        except FileNotFoundError:
            messagebox.showerror("Error", "Aún no hay registros de navegación.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("ERROR: El IDS necesita ejecutarse con 'sudo' para interceptar la red.")
        sys.exit(1)
        
    root = tk.Tk()
    app = AplicacionIDS(root)
    
    def on_closing():
        global ids_corriendo
        ids_corriendo = False
        root.destroy()
        
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()