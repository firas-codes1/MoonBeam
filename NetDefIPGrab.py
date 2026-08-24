import socket
import urllib.request

#Obtain IPs
def ObtainIP():

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        InnIP = s.getsockname()[0]
    except:
        print("Failed to obtain gateway IP")
        return 0
    finally:
        s.close()
        print("Obtained gateway IP address: "+InnIP)

    ExtIP = urllib.request.urlopen('https://ident.me').read().decode('utf8')
    print("Obtained external IP address: "+ExtIP)
    return [InnIP, ExtIP]

