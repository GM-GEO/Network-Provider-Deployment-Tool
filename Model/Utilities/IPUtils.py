import ipaddress
from Model.Utilities.LoggingUtils import Logger_GetLogger


def checkValidIPAddress(IPAddress):
    log = Logger_GetLogger()
    ValidIPAddress = False
    try:
        ipaddress.ip_address(IPAddress)
        ValidIPAddress = True
    except ValueError:
        log.info('address/netmask is invalid: %s' % IPAddress)

    return ValidIPAddress