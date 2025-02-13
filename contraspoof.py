import subprocess
import time

# Esta función obtiene la tabla ARP actual del sistema,
# ejecutando el comando 'arp -n' y procesando su salida
# para crear un diccionario de IP-MAC
def obtener_tabla_arp():
    tabla_arp = {}
    resultado = subprocess.check_output(["arp", "-n"]).decode()
    lineas = resultado.split("\n")
    for linea in lineas[1:]:
        if linea:
            partes = linea.split()
            ip = partes[0]
            mac = partes[2]
            tabla_arp[ip] = mac
    return tabla_arp

# Esta función restablece una entrada específica en la tabla ARP,
# utilizando el comando 'arp -s' para establecer una entrada estática
def restablecer_arp(ip, mac):
    print(f"Restableciendo IP {ip} a MAC {mac}")
    subprocess.call(["arp", "-s", ip, mac])

# Esta función monitorea continuamente la tabla ARP,
# comparando la tabla actual con la original y detectando cambios.
# Si se detecta un cambio, restablece la entrada original.
def monitorizar_tabla_arp(tabla_arp_original):
    while True:
        tabla_arp_actual = obtener_tabla_arp()
        for ip, mac in tabla_arp_actual.items():
            if ip in tabla_arp_original and tabla_arp_original[ip] != mac:
                print(f"¡Advertencia! La IP {ip} ha sido vulnerada. MAC actual: {mac}, MAC original: {tabla_arp_original[ip]}")
                restablecer_arp(ip, tabla_arp_original[ip])
            else:
                print(f"Verificación correcta para IP {ip}: MAC {mac}")
        time.sleep(10)  # Espera 10 segundos antes de volver a comprobar

# Esta es la función principal que inicia el programa.
# Obtiene la tabla ARP original e inicia el monitoreo continuo.
def main():
    print("Obteniendo tabla ARP original...")
    tabla_arp_original = obtener_tabla_arp()
    print("Tabla ARP original obtenida:")
    print(tabla_arp_original)
    
    try:
        monitorizar_tabla_arp(tabla_arp_original)
    except KeyboardInterrupt:
        print("Deteniendo el monitor de la tabla ARP")

# Este bloque asegura que la función main() se ejecute
# solo si el script se ejecuta directamente
if __name__ == "__main__":
    main()
