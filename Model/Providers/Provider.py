from enum import Enum
import logging


class Provider:

    def __init__(self):

        self.hostObjectList = []
        self.networkObjectList = []
        self.objectGroupList = []
        self.URLObjectList = []
        self.FQDNObjectList = []

        self.portObjectList = self.__getPortObjects()
        self.securityZoneObjectList = self.__getSecurityZones()
        self.filePolicyObjectList = self.__getFilePolicies()
        self.urlCategoryObjectList = self.__getURLCategories()
        self.applicationObjectList = self.__getApplications()
        self.allNetworkGroupObjectList = self.__getAllNetworkGroups()
        self.allNetworkObjectList = self.__getAllNetworks()
        self.allGroupsList = self.__getAllGroups()
        self.allUrlGroupList = self.__getAllUrlGroups()
        self.allUrlObjectList = self.__getAllUrls()
        self.allHostObjectList = self.__getAllHosts()

        return None


def checkServiceProvider(serviceProvider):
    validServiceProvider = False
    log = logging.getLogger()

    if serviceProvider in ServiceProvider.list() :
        validServiceProvider = True
        log.info("Service Provider Selected. {Service Provider:" + serviceProvider + "}")
    else:
        validServiceProvider = False

    return validServiceProvider


class ExtendedEnum(Enum):

    @classmethod
    def list(cls):
        return list(map(lambda c: c.value, cls))


class ServiceProvider(ExtendedEnum):
    FMC = 'FMC'
    PALOALTO = 'Palo Alto'
