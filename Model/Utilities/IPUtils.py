import ipaddress
from Model.Utilities.LoggingUtils import Logger_GetLogger


def checkValidIPAddress(IPAddress: str):
    """Validates if the IP address entered was valid

    Args:
        IPAddress (str): The IP address to validate

    Returns:
        bool: Returns if the IP Address entered was valid
    """
    log = Logger_GetLogger()
    ValidIPAddress = False
    try:
        ipaddress.ip_address(IPAddress)
        ValidIPAddress = True
    except ValueError:
        log.info('address/netmask is invalid: %s' % IPAddress)

    return ValidIPAddress