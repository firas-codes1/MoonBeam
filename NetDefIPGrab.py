import socket
import urllib.request

#Obtain IPs
def ObtainIP():
    LocalIP = socket.gethostbyname(socket.gethostname())
    print("Obtained local IP address: "+LocalIP)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        InnIP = s.getsockname()[0]
    except:
        print("Failed to obtain internal IP")
        return 0
    finally:
        s.close()
        print("Obtained internal IP address: "+InnIP)

    ExtIP = urllib.request.urlopen('https://ident.me').read().decode('utf8')
    print("Obtained external IP address: "+ExtIP)
    return [LocalIP, InnIP, ExtIP]

