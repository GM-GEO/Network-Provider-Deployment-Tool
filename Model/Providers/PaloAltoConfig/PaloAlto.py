import requests
from requests.auth import HTTPBasicAuth
from Model.Providers.Provider import Provider, buildUrlForResource, buildUrlForResourceWithId
from Model.DataObjects import Host, Network, Port, FQDN, ObjectGroup, Application, AllGroupObjects, AllNetworksObject
from Model.Utilities.LoggingUtils import Logger_GetLogger
import xml.etree.ElementTree as ET
from Model.RulesObjects import AccessPolicy, ApplicationCategory, ApplicationRisk, ApplicationType, FilePolicy, SecurityZones, URL, URLCategory


class PaloAlto(Provider):
    def __init__(self, ipAddress):
        self.logger = Logger_GetLogger()

        self.paloAltoIP = ipAddress
        self.apiKey = self.requestApiKey()
        self.authHeader = {"X-PAN-KEY": self.apiKey}

        self.hostObjectList = []
        self.networkObjectList = []
        self.objectGroupList = []
        self.URLObjectList = []
        self.FQDNObjectList = []



        self.domainLocation = "/restapi/v10.2"

        self.networkLocation = "/Objects/Addresses"
        self.networkGroupLocation = "/Objects/AddressGroups"
        self.urlLocation = "/Objects/CustomURLCategories"
        self.urlGroupLocation = "/Objects/CustomURLCategories"
        self.securityZoneLocation = "/Network/ZoneProtectionNetworkProfiles"
        self.portLocation = "/Objects/Services"
        self.urlCategoryLocation = "/Objects/CustomURLCategories" #Check this
        self.applicationLocation = "/Objects/Applications"
        self.hostLocation = "/object/hosts"

        self.filePolicyLocation = "/policy/filepolicies"





        self.portObjectList = self.__getAllPorts()
        self.securityZoneObjectList = self.__getAllSecurityZones()
        # self.filePolicyObjectList = self.__getFilePolicies()
        # self.urlCategoryObjectList = self.__getURLCategories()
        self.applicationObjectList = self.__getAllApplications()
        # # self.allNetworkGroupObjectList = self.__getAllNetworkGroups()
        self.allNetworkObjectList = self.__getAllNetworks()
        # self.allGroupsList = self.__getAllGroups()
        # # self.allUrlGroupList = self.__getAllUrlGroups()
        self.allUrlObjectList = self.__getAllURLs()
        # self.allHostObjectList = self.__getAllHosts()


    def requestApiKey(self):
        """
        Retrieve the API key
        :return:
        """
        params = {
            "type": "keygen",
            "user": "admin",
            "password": "estiP@n2022"
        }

        response = requests.get(
            'https://10.255.20.11/api/',
            params=params,
            data={},
            verify=False
        )
        tree = ET.fromstring(response.content)
        api_key = tree[0][0].text

        return api_key

    def __getAllNetworks(self):
        url = buildUrlForResource(self.paloAltoIP, self.domainLocation, '', self.networkLocation)
        params = {
            "location": "vsys",
            "vsys": "vsys1",
        }
        response = requests.get(
            url=url,
            headers=self.authHeader,
            params=params,
            verify=False
        )

        returnList = []

        list_networks = response.json()['result']['entry']
        for network in list_networks:
            type=''
            value=''
            if 'ip-netmask' in network:
                type = 'ip-netmask'
                value = network['ip-netmask']
            if 'fqdn' in network:
                type = 'fqdn'
                value = network['fqdn']
            if 'ip-range' in network:
                type = 'ip-range'
                value = network['ip-range']
            if 'ip-wildcard' in network:
                type = 'ip-wildcard'
                value = network['ip-wildcard']
            temp = [network['@name'], network['@location'], network['@vsys'], type, value]
            returnList.append(temp)
        print("Networks: ", returnList)
        return returnList

    def __getAllURLs(self):
        url = buildUrlForResource(self.paloAltoIP, self.domainLocation, '', self.urlLocation)
        params = {
            "location": "vsys",
            "vsys": "vsys1",
        }
        response = requests.get(
            url=url,
            headers=self.authHeader,
            params=params,
            verify=False
        )

        returnList = []

        list_networks = response.json()['result']['entry']
        for network in list_networks:
            temp = [network['@name'], network['@location'], network['@vsys'], network['list']['member'], network['type']]
            returnList.append(temp)
        print("URLs: ", returnList)
        return returnList
        # return returnList


    def __getAllPorts(self):
        url = buildUrlForResource(self.paloAltoIP, self.domainLocation, '', self.portLocation)
        params = {
            "location": "vsys",
            "vsys": "vsys1",
        }
        response = requests.get(
            url=url,
            headers=self.authHeader,
            params=params,
            verify=False
        )

        returnList = []

        list_networks = response.json()['result']['entry']
        for network in list_networks:
            temp = [network['@name'], network['@location'], network['@vsys'], network['protocol']]
            returnList.append(temp)
        print("Ports: ", returnList)
        return returnList

    def __getAllSecurityZones(self):
        url = buildUrlForResource(self.paloAltoIP, self.domainLocation, '', self.securityZoneLocation)
        params = {
            "location": "panorama-pushed"
        }
        response = requests.get(
            url=url,
            headers=self.authHeader,
            params=params,
            verify=False
        )

        print("SecurityZones: ", response.json()) # Look into it. Not giving anything in the body yet

    def __getAllApplications(self):
        url = buildUrlForResource(self.paloAltoIP, self.domainLocation, '', self.applicationLocation)
        params = {
            "location": "vsys",
            "vsys": "vsys1",
        }
        response = requests.get(
            url=url,
            headers=self.authHeader,
            params=params,
            verify=False
        )

        returnList = []

        list_networks = response.json()['result']['entry']
        for network in list_networks:
            temp = [network['@name'], network['@location'], network['@vsys'], network['category']]
            returnList.append(temp)
        print("Applications: ", returnList)
        return returnList

    # def __addHost(self, name: str, value: str, description='', group=''):
    #     hostObj = Host.HostObject.PaloAltHost(self, name, value, description, group)
    #     # self.logger.info("Host added. {Name: " + name + ", Group: " + group + "}")
    #     return self.hostObjectList.append(hostObj)

    def __addNetwork(self, name, value, description, group):

        networkObj = Network.NetworkObject.PaloAltNetwork(self, name, value, description, group)

        return self.networkObjectList.append(networkObj)

    def __addURL(self, name, value, description, group):

        urlObj = URL.URLObject.PaloAltoUrlObject(self, name, value, description, group)

        return self.URLObjectList.append(urlObj)

    def __addFQDN(self, name, value, description='', group=''):

        fqdnObj = FQDN.FQDNObject.PaloAltoFQDN(self, name, value, description, group)

        return self.FQDNObjectList.append(fqdnObj)

    def addObject(self, domain, type, name, value, description='', group=''):

        # if type == 'host':
        #     self.__addHost(name, value, description, group)

        if type == 'network':
            self.__addNetwork(name, value, description, group)

        elif type == 'url':
            self.__addURL(name, value, description, group)

        elif type == 'fqdn':
            self.__addFQDN(name, value, description, group)

        else:
            return "Object type not configured"

    def getObjectList(self, objectType):

        match objectType:
            # case "host":
            #     return self.hostObjectList
            case "network":
                return self.networkObjectList
            case "url":
                return self.URLObjectList
            case "fqdn":
                return self.FQDNObjectList
            case "port":
                return self.portObjectList
            case "securityzone":
                return self.securityZoneObjectList
            case _:
                return None

    def applyObjectList(self, listType):
        match listType:
            case "network":
                for network in self.networkObjectList:
                    print("Name: ", network.getName(), "Value: ", network.getValue(), "Group: ", network.getGroupMembership(), "Description: ", network.getDescription())
                    for i in self.allNetworkObjectList:
                        if network.getName() == i[0]:
                            print("Match found.")



