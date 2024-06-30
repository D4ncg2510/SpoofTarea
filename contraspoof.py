import subprocess
import scapy.all as scapy
import time

def obtener_tabla_arp():
    tabla_arp = {}
    solicitud_arp = scapy.ARP(pdst="192.168.64.0/24")
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    solicitud_broadcast = broadcast/solicitud_arp
    lista_contestada = scapy.srp(solicitud_broadcast, timeout=1, verbose=False)[0]

    for elemento in lista_contestada:
        tabla_arp[elemento[1].psrc] = elemento[1].hwsrc

    return tabla_arp

def restaurar_arp(ip_objetivo, mac_objetivo, ip_router, mac_router):
    paquete = scapy.ARP(op=2, pdst=ip_objetivo, hwdst=mac_objetivo, psrc=ip_router, hwsrc=mac_router)
    scapy.send(paquete, verbose=False)

def monitorear_tabla_arp(tabla_arp_original):
    while True:
        tabla_arp_actual = obtener_tabla_arp()
        for ip, mac in tabla_arp_original.items():
            if ip in tabla_arp_actual and tabla_arp_actual[ip] != mac:
                print(f"ALERTA: Se ha detectado un cambio en la IP {ip}. MAC original: {mac}, MAC actual: {tabla_arp_actual[ip]}")
                # Restaurar la dirección MAC original del router despues de detectar el cambio
                restaurar_arp(ip, mac, ip_router="192.168.64.1", mac_router="00:00:00:00:00:01")
        time.sleep(10)  # Espera 10 segundos antes de volver a comprobar

def principal():
    print("Obteniendo tabla ARP original...")
    tabla_arp_original = obtener_tabla_arp()
    print("Tabla ARP original obtenida.")
    
    monitorear_tabla_arp(tabla_arp_original)

if __name__ == "__main__":
    principal()
