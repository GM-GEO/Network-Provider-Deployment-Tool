import requests
from requests.auth import HTTPBasicAuth
from Model.Providers.Provider import Provider, buildUrlForResource, buildUrlForResourceWithId
from Model.DataObjects import Host, Network, Port, FQDN, ObjectGroup, Application, AllGroupObjects, AllNetworksObject
from Model.Utilities.LoggingUtils import Logger_GetLogger
from Model.DataObjects.Enums.GroupTypeEnum import GroupTypeEnum
from Model.DataObjects.Enums.YesNoEnum import YesNoEnum
from Model.DataObjects.Enums.ObjectTypeEnum import ObjectTypeEnum
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
        self.urlCategoryLocation = "/Objects/CustomURLCategories"  #Check this
        self.applicationLocation = "/Objects/Applications"
        # self.hostLocation = "/object/hosts"

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
        params = {"type": "keygen", "user": "admin", "password": "estiP@n2022"}

        response = requests.get('https://10.255.20.11/api/',
                                params=params,
                                data={},
                                verify=False)
        tree = ET.fromstring(response.content)
        api_key = tree[0][0].text

        return api_key

    def __getAllNetworks(self):
        url = buildUrlForResource(self.paloAltoIP, self.domainLocation, '',
                                  self.networkLocation)
        params = {
            "location": "vsys",
            "vsys": "vsys1",
        }
        response = requests.get(url=url,
                                headers=self.authHeader,
                                params=params,
                                verify=False)

        returnList = []

        list_networks = response.json()['result']['entry']
        for network in list_networks:
            type = ''
            value = ''
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
            temp = [
                network['@name'], network['@location'], network['@vsys'], type,
                value
            ]
            returnList.append(temp)
        print("Networks: ", returnList)
        return returnList

    def __getAllURLs(self):
        url = buildUrlForResource(self.paloAltoIP, self.domainLocation, '',
                                  self.urlLocation)
        params = {
            "location": "vsys",
            "vsys": "vsys1",
        }
        response = requests.get(url=url,
                                headers=self.authHeader,
                                params=params,
                                verify=False)

        returnList = []

        list_networks = response.json()['result']['entry']
        for network in list_networks:
            temp = [
                network['@name'], network['@location'], network['@vsys'],
                network['list']['member'], network['type']
            ]
            returnList.append(temp)
        print("URLs: ", returnList)
        return returnList
        # return returnList

    def __getAllPorts(self):
        url = buildUrlForResource(self.paloAltoIP, self.domainLocation, '',
                                  self.portLocation)
        params = {
            "location": "vsys",
            "vsys": "vsys1",
        }
        response = requests.get(url=url,
                                headers=self.authHeader,
                                params=params,
                                verify=False)

        returnList = []
        list_networks = {}

        if response.json()['result']['entry']:
            list_networks = response.json()['result']['entry']
        for network in list_networks:
            temp = [
                network['@name'], network['@location'], network['@vsys'],
                network['protocol']
            ]
            returnList.append(temp)
        print("Ports: ", returnList)
        return returnList

    def __getAllSecurityZones(self):
        url = buildUrlForResource(self.paloAltoIP, self.domainLocation, '',
                                  self.securityZoneLocation)
        params = {"location": "panorama-pushed"}
        response = requests.get(url=url,
                                headers=self.authHeader,
                                params=params,
                                verify=False)

        print("SecurityZones: ", response.json()
              )  # Look into it. Not giving anything in the body yet

    def __getAllApplications(self):
        url = buildUrlForResource(self.paloAltoIP, self.domainLocation, '',
                                  self.applicationLocation)
        params = {
            "location": "vsys",
            "vsys": "vsys1",
        }
        response = requests.get(url=url,
                                headers=self.authHeader,
                                params=params,
                                verify=False)

        returnList = []

        list_networks = response.json()['result']['entry']
        for network in list_networks:
            temp = [
                network['@name'], network['@location'], network['@vsys'],
                network['category']
            ]
            returnList.append(temp)
        print("Applications: ", returnList)
        return returnList

    def __addHost(self, name: str, value: str, description='', group=''):
        hostObj = Host.HostObject.PaloAltoHost(self, name, value, description,
                                               group)
        return self.hostObjectList.append(hostObj)

    def __addNetwork(self, name, value, description, group):

        networkObj = Network.NetworkObject.PaloAltNetwork(
            self, name, value, description, group)

        return self.networkObjectList.append(networkObj)

    def __addURL(self, name, value, description, group):

        urlObj = URL.URLObject.PaloAltoUrlObject(self, name, value,
                                                 description, group)

        return self.URLObjectList.append(urlObj)

    def __addFQDN(self, name, value, description='', group=''):

        fqdnObj = FQDN.FQDNObject.PaloAltoFQDN(self, name, value, description,
                                               group)

        return self.FQDNObjectList.append(fqdnObj)

    def addObject(self, type, name, value, description='', group=''):

        if type == 'host':
            self.__addHost(name, value, description, group)

        if type == 'network':
            self.__addNetwork(name, value, description, group)

        elif type == 'url':
            self.__addURL(name, value, description, group)

        elif type == 'fqdn':
            self.__addFQDN(name, value, description, group)

        else:
            return "Object type not configured"

    def getObjectList(self, objectType):

        if type == ObjectTypeEnum.HOST:
            return self.hostObjectList

        if type == ObjectTypeEnum.NETWORK:
            return self.networkObjectList

        elif type == ObjectTypeEnum.URL:
            return self.URLObjectList

        elif type == ObjectTypeEnum.FQDN:
            return self.FQDNObjectList

        elif type == ObjectTypeEnum.SECURITYZONE:
            return self.securityZoneObjectList
        else:
            return "Object type not configured"

    def deleteNetwork(self, name):
        """
        Deletes address/network objects in Palo Alto. It can delete the addresses of all types,
        that is of type 'ip-netmask', 'fqdn', 'ip-range', and 'ip-wildcard' given the correct name is passed as parameter.
        :param name: The name of the address object to be deleted
        :return: status code of the response
        """
        queryparams = {}
        queryparams['location'] = 'vsys'
        queryparams['vsys'] = 'vsys1'
        queryparams['name'] = name

        url = buildUrlForResource(self.paloAltoIP, self.domainLocation, '',
                                  self.networkLocation)

        response = requests.delete(url=url,
                                   headers=self.authHeader,
                                   params=queryparams,
                                   verify=False)

        return response.status_code

    def deleteURL(self, name):
        queryparams = {}
        queryparams['location'] = 'vsys'
        queryparams['vsys'] = 'vsys1'
        queryparams['name'] = name

        url = buildUrlForResource(self.paloAltoIP, self.domainLocation, '',
                                  self.urlLocation)

        response = requests.delete(url=url,
                                   headers=self.authHeader,
                                   params=queryparams,
                                   verify=False)

        return response.status_code

    def applyObjectList(self, listType):

        if type == ObjectTypeEnum.HOST:
            for host in self.hostObjectList:
                flag_host = True
                print("Name: ", host.getPName(), "Value: ", host.getPValue(),
                      "Group: ", host.getGroupMembership())
                for i in self.allNetworkObjectList:
                    if host.getPName() == i[0]:
                        flag_host = False
                        print("Match found")
                        print(i)
                        if host.getPName() == i[0] and host.getPValue(
                        ) == i[4] and i[3] == 'ip-netmask':
                            print("False 1 loop")
                            print(
                                "An object with the exact same name, type and value exists, so no need to recreate it."
                            )
                        else:
                            print(
                                "There exists a different object with the same name. Do you want to delete the existing object and create the current one? Please answer Y/N: "
                            )
                            ans = str(input())
                            if ans == 'Y':
                                del_response = self.deleteNetwork(
                                    host.getPName())
                                if del_response < 299:
                                    self.allNetworkObjectList.remove(i)
                                create_response = host.createHost(
                                    self.authHeader)
                                if create_response < 299:
                                    self.allNetworkObjectList.append([
                                        host.getPName(), 'vsys', 'vsys1',
                                        'ip-netmask',
                                        host.getPValue()
                                    ])
                if flag_host == True:
                    print("True loop")
                    create_response = host.createHost(self.authHeader)
                    if create_response < 299:
                        self.allNetworkObjectList.append([
                            host.getPName(), 'vsys', 'vsys1', 'ip-netmask',
                            host.getPValue()
                        ])
            pass

        if type == ObjectTypeEnum.NETWORK:
            for network in self.networkObjectList:
                flag_network = True
                print("Name: ", network.getPName(), "Value: ",
                      network.getPValue(), "Group: ",
                      network.getGroupMembership())
                for i in self.allNetworkObjectList:
                    if network.getPName() == i[0]:
                        flag_network = False
                        print("Match found")
                        print(i)
                        if network.getPName() == i[0] and network.getPValue(
                        ) == i[4] and i[3] == 'ip-netmask':
                            print("False 1 loop")
                            print(
                                "An object with the exact same name, type and value exists, so no need to recreate it."
                            )
                        else:
                            print(
                                "There exists a different object with the same name. Do you want to delete the existing object and create the current one? Please answer Y/N: "
                            )
                            ans = str(input())
                            if ans == 'Y':
                                del_response = self.deleteNetwork(
                                    network.getPName())
                                if del_response < 299:
                                    self.allNetworkObjectList.remove(i)
                                create_response = network.createNetwork(
                                    self.authHeader)
                                if create_response < 299:
                                    self.allNetworkObjectList.append([
                                        network.getPName(), 'vsys', 'vsys1',
                                        'ip-netmask',
                                        network.getPValue()
                                    ])
                if flag_network == True:
                    print("True loop")
                    create_response = network.createNetwork(self.authHeader)
                    if create_response < 299:
                        self.allNetworkObjectList.append([
                            network.getPName(), 'vsys', 'vsys1', 'ip-netmask',
                            network.getPValue()
                        ])
            pass

        elif type == ObjectTypeEnum.URL:
            for url in self.URLObjectList:
                flag_fqdn = True
                print("Name: ", url.getPName(), "Value: ", url.getPValue(),
                      "Group: ", url.getGroupMembership())
                for i in self.allUrlObjectList:
                    if url.getPName() == i[0]:
                        flag_fqdn = False
                        print("Match found")
                        print("i value: ", i)
                        if url.getPName() == i[0] and url.getPValue() == i[3]:
                            print("False 1 loop")
                            print(
                                "An object with the exact same name, type and value exists, so no need to recreate it."
                            )
                        else:
                            print(
                                "There exists a different object with the same name. Do you want to delete the existing object and create the current one? Please answer Y/N: "
                            )
                            ans = str(input())
                            if ans == 'Y':
                                del_response = self.deleteURL(url.getPName())
                                if del_response < 299:
                                    self.allUrlObjectList.remove(i)
                                create_response = url.createURL(
                                    self.authHeader)
                                if create_response < 299:
                                    self.allUrlObjectList.append([
                                        url.getPName(), 'vsys', 'vsys1',
                                        url.getPValue(), 'URL List'
                                    ])
                if flag_fqdn == True:
                    print("True loop")
                    create_response = url.createURL(self.authHeader)
                    if create_response < 299:
                        self.allUrlObjectList.append([
                            url.getPName(), 'vsys', 'vsys1',
                            url.getPValue(), 'URL list'
                        ])
            pass

        elif type == ObjectTypeEnum.FQDN:
            for fqdn in self.FQDNObjectList:
                flag_fqdn = True
                print("Name: ", fqdn.getPName(), "Value: ", fqdn.getPValue(),
                      "Group: ", fqdn.getGroupMembership())
                for i in self.allNetworkObjectList:
                    if fqdn.getPName() == i[0]:
                        flag_fqdn = False
                        print("Match found")
                        print(i)
                        if fqdn.getPName() == i[0] and fqdn.getPValue(
                        ) == i[4] and i[3] == 'fqdn':
                            print("False 1 loop")
                            print(
                                "An object with the exact same name, type and value exists, so no need to recreate it."
                            )
                        else:
                            print(
                                "There exists a different object with the same name. Do you want to delete the existing object and create the current one? Please answer Y/N: "
                            )
                            ans = str(input())
                            if ans == 'Y':
                                del_response = self.deleteNetwork(
                                    fqdn.getPName())
                                if del_response < 299:
                                    self.allNetworkObjectList.remove(i)
                                create_response = fqdn.createFQDN(
                                    self.authHeader)
                                if create_response < 299:
                                    self.allNetworkObjectList.append([
                                        fqdn.getPName(), 'vsys', 'vsys1',
                                        'fqdn',
                                        fqdn.getPValue()
                                    ])
                if flag_fqdn == True:
                    print("True loop")
                    create_response = fqdn.createFQDN(self.authHeader)
                    if create_response < 299:
                        self.allNetworkObjectList.append([
                            fqdn.getPName(), 'vsys', 'vsys1', 'fqdn',
                            fqdn.getPValue()
                        ])
            pass

    def createGroupMembershipLists(self, type):
        groupDict = {}
        if type == 'url':
            for url in self.URLObjectList:
                urlName = url.getGroupMembership()
                if urlName not in groupDict:
                    groupDict[urlName] = []
                    groupDict[urlName].append(url.getPValue())

                else:
                    groupDict[urlName].append(url.getPValue())

        return groupDict

    def createGroups(self, type):
        groupDict = self.createGroupMembershipLists(type)
