from enum import Enum
from tokenize import String
from Model.Utilities.LoggingUtils import Logger_GetLogger
from Model.Utilities.ExtendedEnum import ExtendedEnum


class Provider:

    def __init__(self):

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


def checkServiceProvider(serviceProvider: str):
    """Checks the selection of Service Provider entered by the user

    Args:
        serviceProvider (str): The name of the service provider from the ProviderEnum list

    Returns:
        bool: Returns if the entered value was in the ProviderEnum list
    """
    validServiceProvider = False
    log = Logger_GetLogger()

    if serviceProvider in ProviderEnum.list():
        validServiceProvider = True
        log.info("Service Provider Selected. {Service Provider:" +
                 serviceProvider + "}")
    else:
        validServiceProvider = False

    return validServiceProvider


def buildUrlForResourceWithId(IpAddress: str, domainLocation: str,
                              domainId: str, resourceLocation: str, id: str):
    """Build an https prefixed resource endpoint to use for CRUD operations

    Args:
        IpAddress (string): The address of the service provider
        domainLocation (string): The domain configuration
        domainId (string): The GUID of the domain that is being targeted
        resourceLocation (string): The location of the resource group
        id (string): The guid of the specific item being retrieved

    Returns:
        string: the fully qualified URL resource
    """
    ourString = 'https://{0}{1}{2}{3}/{4}'.format(IpAddress, domainLocation,
                                                  domainId, resourceLocation,
                                                  id)
    return ourString


def buildUrlForResource(IpAddress: str, domainLocation: str, domainId: str,
                        resourceLocation: str):
    """Build an https prefixed resource endpoint to use for CRUD operations

    Args:
        IpAddress (string): The address of the service provider
        domainLocation (string): The domain configuration
        domainId (string): The GUID of the domain that is being targeted. Domain Id can be left blank if there is no domain Id
        resourceLocation (string): The location of the resource group

    Returns:
        string: the fully qualified URL resource
    """
    return 'https://{0}{1}{2}{3}'.format(IpAddress, domainLocation, domainId,
                                         resourceLocation)


class ProviderEnum(ExtendedEnum):
    FMC = 'FMC'
    PALOALTO = 'Palo Alto'
