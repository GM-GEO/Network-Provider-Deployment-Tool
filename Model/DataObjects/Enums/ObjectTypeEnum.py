from typing import Literal
from Model.Utilities.ExtendedEnum import ExtendedEnum


class ObjectTypeEnum(ExtendedEnum):
    HOST = 'host'
    NETWORK = 'network'
    URL = 'url'
    FQDN = 'fqdn'
    SECURITYZONE = 'securityzone'
    PORT = 'port'
