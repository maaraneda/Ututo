from scapy.all import sniff, Ether, ARP, IP, TCP, UDP
from termcolor import colored

banner = """
░░░░░░▄█▄█░░░░░▄░░░░░░
░░░░██████░░░░░░█░░░░░
░░░░░░███████████░░░░░
▒▒▒▒▒▒█▀▀█▀▀██▀██▒▒▒▒▒
▒▒▒▒▒▄█▒▄█▒▒▄█▒▄█▒▒▒▒▒
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒~Ututo▒
"""

# Cargar OUI desde el archivo oui.txt
def load_oui_file(filename):
    oui_dict = {}
    with open(filename, 'r') as file:
        for line in file:
            # Ignorar líneas vacías o comentarios
            if not line.strip() or line.startswith('#'):
                continue
            
            parts = line.split('\t')
            if len(parts) >= 3:
                oui = parts[0].strip().upper()  # OUI en mayúsculas
                manufacturer = parts[2].strip()  # Nombre del fabricante
                oui_dict[oui] = manufacturer
    return oui_dict

# Función para obtener el fabricante de una dirección MAC
def get_mac_vendor(mac, oui_dict):
    # Extraer los primeros 6 caracteres (OUI) de la MAC
    oui = mac[:8].upper()  # Formato OUI: XX:XX:XX
    return oui_dict.get(oui, "Desconocido")

# Conjunto para almacenar registros únicos
seen_packets = set()
print(colored(banner, 'green'))

# Cargar OUI en el script
oui_dict = load_oui_file('oui.txt')

def process_packet(packet):
    # Crear una representación del paquete como tupla para evitar duplicados
    packet_summary = ""

    if Ether in packet:
        mac_src = packet[Ether].src
        mac_dst = packet[Ether].dst
        vendor_src = get_mac_vendor(mac_src, oui_dict)
        vendor_dst = get_mac_vendor(mac_dst, oui_dict)
        packet_summary += f"{colored('MAC Origen:', 'cyan')} {mac_src} ({vendor_src}), {colored('MAC Destino:', 'cyan')} {mac_dst} ({vendor_dst});\n"

    if ARP in packet:
        packet_summary += f"{colored('Trama ARP detectada:', 'yellow')} {packet.summary()};\n"

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_summary += f"{colored('IP Origen:', 'green')} {src_ip}, {colored('IP Destino:', 'green')} {dst_ip};\n"

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            packet_summary += f"{colored('TCP Origen Puerto:', 'blue')} {src_port}, {colored('TCP Destino Puerto:', 'blue')} {dst_port};\n"

        if UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            packet_summary += f"{colored('UDP Origen Puerto:', 'magenta')} {src_port}, {colored('UDP Destino Puerto:', 'magenta')} {dst_port};\n"

    # Verificar si el paquete ya fue registrado
    if packet_summary and packet_summary not in seen_packets:
        seen_packets.add(packet_summary)
        print(packet_summary)

# Capturar el tráfico en la interfaz deseada
# Cambia 'eth0' por la interfaz que estés utilizando
sniff(iface="eth0", prn=process_packet, store=0)
