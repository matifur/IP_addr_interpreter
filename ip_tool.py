import ipaddress
import argparse


def validate_netmask(mask):
    """Sprawdza poprawność maski sieci w formacie dziesiętnym."""
    try:
        network = ipaddress.IPv4Network(f"0.0.0.0/{mask}", strict=False)
        return network.prefixlen
    except ValueError:
        raise ValueError(f"Nieprawidłowa maska sieci: {mask}")


def parse_ip_and_mask(ip, mask=None):
    """
    Rozpoznaje, czy podano CIDR (np. 192.168.1.1/24) czy maskę dziesiętną (np. 192.168.1.1 255.255.255.0)
    lub CIDR z odstępem (np. 192.168.1.1 /24).
    """
    try:
        # Jeśli maska zaczyna się od "/", traktujemy ją jako CIDR
        if mask and mask.startswith("/"):
            prefixlen = int(mask[1:])
            if ":" in ip and not (0 <= prefixlen <= 128):  # IPv6
                raise ValueError(f"Nieprawidłowa wartość prefiksu IPv6: {prefixlen}")
            elif "." in ip and not (0 <= prefixlen <= 32):  # IPv4
                raise ValueError(f"Nieprawidłowa wartość prefiksu IPv4: {prefixlen}")
            return ipaddress.ip_interface(f"{ip}/{prefixlen}")

        # Jeśli podano jeden parametr, sprawdzamy, czy jest w formacie CIDR
        if mask is None:
            if "/" in ip:
                ip = ip.replace(" ", "")  # Usuwamy potencjalne spacje w formacie CIDR
                return ipaddress.ip_interface(ip)
            else:
                raise ValueError("Brak CIDR lub maski dziesiętnej.")

        # Jeśli podano maskę dziesiętną, konwertujemy ją na prefix
        prefixlen = validate_netmask(mask)
        return ipaddress.ip_interface(f"{ip}/{prefixlen}")

    except ValueError as e:
        raise ValueError(f"Błąd w przetwarzaniu adresu: {e}")


def check_special_address(ip_obj):
    """Sprawdza, czy adres należy do specjalnych kategorii."""
    ip = ip_obj.ip
    if ip.is_loopback:
        return "Loopback"
    elif ip.is_multicast:
        return "Multicast"
    elif ip.is_private:
        return "Prywatny (RFC1918)"
    elif ip.is_link_local:
        return "APIPA (Link-local)"
    elif ip.is_reserved:
        return "Zarezerwowany"
    elif ip.is_unspecified:
        return "Nieokreślony (Unspecified)"
    else:
        return "Brak specjalnej kategorii"


def ip_info(ip_obj):
    """Wyświetla szczegółowe informacje o adresie IP."""
    ip_version = ip_obj.version
    ip_address = ip_obj.ip
    network_address = ip_obj.network.network_address
    netmask = ip_obj.network.netmask
    broadcast_address = ip_obj.network.broadcast_address if ip_version == 4 else "N/A"
    num_hosts = ip_obj.network.num_addresses - 2 if ip_version == 4 else ip_obj.network.num_addresses
    binary_representation = ''.join(f'{int(octet):08b}' for octet in ip_address.packed)
    hex_representation = ip_address.exploded

    print("Informacje o adresie IP:")
    print(f"Typ adresu: IPv{ip_version}")
    print(f"Adres IP: {ip_address}")
    print(f"Adres sieci: {network_address}")
    print(f"Maska sieci: {netmask}")
    print(f"Adres rozgłoszeniowy: {broadcast_address}")
    print(f"Liczba hostów w sieci: {num_hosts}")
    print(f"Reprezentacja binarna: {binary_representation}")
    print(f"Reprezentacja szesnastkowa: {hex_representation}")
    print(f"Kategoria adresu: {check_special_address(ip_obj)}")


def is_ip_in_subnet(ip, subnet):
    """Sprawdza, czy adres IP należy do podanej podsieci."""
    try:
        subnet_obj = ipaddress.ip_network(subnet, strict=False)
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj in subnet_obj
    except ValueError as e:
        print(f"Błąd: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Podręczne narzędzie sieciowe.")
    parser.add_argument("ip", help="Adres IP w formacie CIDR (np. 192.168.1.1/24) lub adres z maską dziesiętną (np. 192.168.1.1 255.255.255.0).", nargs='+')
    parser.add_argument("-n", "--network", help="Adres podsieci do sprawdzenia przynależności IP.")
    parser.add_argument("-b", "--binary", action="store_true", help="Wyświetla reprezentację binarną.")
    parser.add_argument("-x", "--hex", action="store_true", help="Wyświetla reprezentację szesnastkową.")

    args = parser.parse_args()

    try:
        # Rozpoznanie formatu wejściowego
        if len(args.ip) == 1:
            ip_obj = parse_ip_and_mask(args.ip[0])  # CIDR
        elif len(args.ip) == 2:
            ip_obj = parse_ip_and_mask(args.ip[0], args.ip[1])  # IP + maska dziesiętna lub CIDR z odstępem
        else:
            raise ValueError("Nieprawidłowy format wejściowy. Podaj adres w formacie CIDR lub z maską dziesiętną.")

        ip_info(ip_obj)

        # Sprawdzanie przynależności do podsieci
        if args.network:
            belongs = is_ip_in_subnet(str(ip_obj.ip), args.network)
            print(f"Adres IP {'należy' if belongs else 'nie należy'} do podsieci {args.network}.")

    except ValueError as e:
        print(f"Błąd: {e}")


if __name__ == "__main__":
    main()
