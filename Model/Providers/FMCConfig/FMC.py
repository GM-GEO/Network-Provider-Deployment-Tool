import requests
from requests.auth import HTTPBasicAuth
from Model.DataObjects import Host, Network, Port, FQDN, ObjectGroup, AllGroupObjects, AllNetworksObject
from Model.Providers.Provider import Provider, buildUrlForResource
from Model.RulesObjects import AccessPolicy, ApplicationCategory, ApplicationRisk, ApplicationType, FilePolicy, SecurityZones, URL, URLCategory
from Model.Utilities.LoggingUtils import Logger_GetLogger

class FMC(Provider):
    def __init__(self, ipAddress):
        """Creates the FMC provider with the lists of objects and resource locations

        Args:
            ipAddress (string): The ID Address of the provider

        Notes:
            The domainId attribute is set as part of the self.requestToken() call made
            by the self.apiToken istantiation.

        Returns:
            FMC: An FMC object
        """
        self.logger = Logger_GetLogger()

        self.fmcIP = ipAddress

        self.apiToken = self.requestToken()
        self.domainId = ""

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

        self.authHeader = {"X-auth-access-token": self.apiToken}

        self.domainLocation = "/api/fmc_config/v1/domain/"

        self.networkLocation = "/object/networks/"
        self.networkGroupLocation = "/object/networkgroups/"
        self.urlLocation = "/object/urls"
        self.urlGroupLocation = "/object/urlgroups/"
        self.securityZoneLocation = "/object/securityzones/"
        self.portLocation = "/object/ports/"
        self.urlCategoryLocation = "/object/urlcategories/"
        self.applicationLocation = "/object/applications/"
        self.hostLocation = "/object/hosts/"

        self.filePolicyLocation = "/policy/filepolicies"

        return None

    def requestToken(self):
        """
        We will need to extract these username/password values and either read them from user input or a security key file
        Can we pull the domain ID from this auth request and set it by default?
        """
        response = requests.post(
            'https://' + self.fmcIP + '/api/fmc_platform/v1/auth/generatetoken',
            auth=HTTPBasicAuth('apiuser', 'JR8A54gWFc&#IVxIvoP91@0mWhQ51'),
            data={},
            verify=False
        )

        if response.headers['DOMAIN_UUID']:
            self.domainId = response.headers['DOMAIN_UUID']
            self.logger.info("Domain Id found and set")
            pass

        self.logger.info("Auth token found and set")
        return response.headers['X-auth-access-token']

    def __addHost(self, name:str, value:str, description='', group=''):

        hostObj = Host.HostObject.FMCHost(self, name, value, description, group)
        self.logger.info("Host added. {Name: " + name + ", Group: " + group + "}")
        return self.hostObjectList.append(hostObj)

    def __addNetwork(self, domain, name, value, description='', group=''):

        networkObj = Network.NetworkObject(
            domain, name, value, description, group, self.fmcIP)
        return self.networkObjectList.append(networkObj)

    def __addURL(self, domain, name, url, description='', group=''):

        urlObj = URL.URLObject(
            domain, name, url, description, group, self.fmcIP)
        return self.URLObjectList.append(urlObj)

    def __addFQDN(self, domain, name, value, description='', group=''):

        fqdnObj = FQDN.FQDNObject(
            domain, name, value, description, group, self.fmcIP)

        return self.FQDNObjectList.append(fqdnObj)

    def __createGroupMembershipLists(self, type):

        groupDict = {}

        if type == 'host':
            for host in self.hostObjectList:

                hostName = host.getName()
                hostID = host.getUUID()
                groupName = host.getGroupMembership()

                if groupName not in groupDict:  # If group name is not in the dictionary then we add the group name and associate an empty list with the group and append the values in it
                    groupDict[groupName] = []
                    groupDict[groupName].append({
                        'type': 'Host',
                        'id': hostID,
                        'name': hostName
                    })
                else:
                    groupDict[groupName].append({
                        'type': 'Host',
                        'id': hostID,
                        'name': hostName
                    })
        elif type == 'network':
            for network in self.networkObjectList:

                networkName = network.getName()
                networkID = network.getUUID()
                groupName = network.getGroupMembership()

                if groupName not in groupDict:
                    groupDict[groupName] = []
                    groupDict[groupName].append({
                        'type': 'Network',
                        'id': networkID,
                        'name': networkName
                    })
                else:
                    groupDict[groupName].append({
                        'type': 'Network',
                        'id': networkID,
                        'name': networkName
                    })

        elif type == 'url':
            for url in self.URLObjectList:

                urlName = url.getName()
                urlID = url.getUUID()
                groupName = url.getGroupMembership()

                if groupName not in groupDict:
                    groupDict[groupName] = []
                    groupDict[groupName].append({
                        'type': 'Url',
                        'id': urlID,
                        'name': urlName
                    })

                else:
                    groupDict[groupName].append({
                        'type': 'Url',
                        'id': urlID,
                        'name': urlName
                    })

        print(":GroupDict: ", groupDict)

        return groupDict

    def deleteGroup(self, id, type):
        groupLocation = self.networkGroupLocation if type == "network" else self.urlGroupLocation
        url = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, groupLocation, id)

        networks = requests.delete(
            url=url,
            headers=self.authHeader,
            verify=False
        )

        self.logger.info("Group deleted. {Id: "+ id + ", Type: " + type + "}")
        return networks.status_code

    def createGroups(self, type):

        groupDict = self.__createGroupMembershipLists(type)
        print("All groups list: ", self.allGroupsList)

        for group in groupDict:
            if type == 'host':
                type = 'network'

            objGroup = ObjectGroup.GroupObject(
                self.domainId, group, type, groupDict[group], self.fmcIP)
            flag = True

            for i in self.allGroupsList:
                if i[0] == objGroup.getName():
                    print("This groupName named ", objGroup.getName(),
                          "already exists. Do you want to delete the object group and recreate it? Please answer 'Y' or 'N'. Please note that the existing networks in the group will get deleted from the group.")
                    ans = str(input())
                    if ans == 'N':
                        flag = False
                        print("Continued without deleting and recreating the group.")
                    elif ans == 'Y':
                        flag = False
                        if i[3] == 'NetworkGroup':
                            result = self.deleteGroup(i[1], 'network')
                        else:
                            result = self.deleteGroup(i[1], 'url')

                        if int(result) < 299:
                            self.allGroupsList.remove(i)
                        result = objGroup.createGroup(self.apiToken)
                        print("Making group: ", result)
                        if int(result) < 299:
                            self.allGroupsList.append(
                                [objGroup.getName(), objGroup.getUUID(), 'objects', i[3], groupDict[group]])
                    # if result < 299:
                    #     self.allGroupsList.append([objGroup.getName(), objGroup.getUUID(), ])
                    # self.allGroupsList.remove()
                if flag == True:
                    result = objGroup.createGroup(self.apiToken)
                    print("Making group: ", result)
                    if int(result) < 299:
                        self.allGroupsList.append(
                            [objGroup.getName(), objGroup.getUUID(), 'objects', i[3], groupDict[group]])

            """
            for i in self.allGroupsList:
                print("i: ", i)
                print("group: ", groupDict[group])

                print("Comparison: ", self.compareContainingObjects(i[4], group))
                if i[0] == objGroup.getName():
                    print(i[0], objGroup.getName(), "Results")
                    flag = False
                    check = self.compareContainingObjects(i[4], group)  # gives True if all the component names in group are there in i[3], that is the component column of the group
                    print("Check: ", check)
                    if check == True:
                        print("The groups have same components so no need to delete and recreate the object group")
                    if check == False:
                        print("This groupName named ", objGroup.getName(), "already exists. Do you want to delete the object group and recreate it? Please answer 'Y' or 'N'. Please note that the existing networks in the group will get deleted from the group.")
                        ans = str(input())
                        if ans == 'N':
                            flag = False
                            print("Continued without deleting and recreating the group.")
                        elif ans == 'Y':
                            flag = False
                            if i[3] == 'NetworkGroup':
                                result = self.deleteGroup(i[1], 'network')
                            else:
                                result = self.deleteGroup(i[1], 'url')


                            if int(result) < 299:
                                self.allGroupsList.remove(i)
                            result = objGroup.createGroup(self.apiToken)
                            print("Making group: ", result)
                            if int(result) < 299:
                                self.allGroupsList.append([objGroup.getName(), objGroup.getUUID(), 'objects', i[3], groupDict[group]])
                        # if result < 299:
                        #     self.allGroupsList.append([objGroup.getName(), objGroup.getUUID(), ])
                        # self.allGroupsList.remove()
                if flag == True:
                    print("Reaching here")
                    result = objGroup.createGroup(self.apiToken)
                    print("Making group: ", result)
                    if int(result) < 299:
                        self.allGroupsList.append([objGroup.getName(), objGroup.getUUID(), 'objects', i[3], groupDict[group]])
            """

            self.objectGroupList.append(objGroup)

    def compareContainingObjects(self, groupDict, objectDict):
        if len(groupDict) != len(objectDict):
            return False
        else:
            count = 0
            for group in groupDict:
                for object in objectDict:
                    if object['name'] == group['name']:
                        count = count + 1
            print(count)
            if count == len(groupDict):
                return True
            else:
                return False

    def addObject(self, domain, type, name, value, description='', group=''):

        if type == 'host':
            self.__addHost(name, value, description, group)

        elif type == 'network':
            self.__addNetwork(domain, name, value, description, group)

        elif type == 'url':
            self.__addURL(domain, name, value, description, group)

        elif type == 'fqdn':
            self.__addFQDN(domain, name, value, description, group)

        else:
            return "Object type not configured"

    def getObjectList(self, objectType):

        match objectType:
            case "host":
                return self.hostObjectList
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
            case "host":

                for host in self.hostObjectList:
                    flag_host = True
                    for i in self.allHostObjectList:

                        if i[0] == host.getName():
                            flag_host = False
                            if ((i[0] == host.getName()) and (i[2] == host.getValue())):
                                print(
                                    "Exactly same object so no need to delete. Condition 1.1 ", i[0])
                                flag_network = False
                            elif ((i[0] == host.getName()) and (i[2] != host.getValue())):
                                print(i[0], i[2],
                                      "Condition 1.2: There exists an object with the same name. Do you want to delete the existing object? Please answer Y/N: ")
                                ans = str(input())
                                if ans == 'Y':
                                    print("Condition 1.2.1")
                                    result = self.deleteHosts(i[1])
                                    if int(result) <= 299 and int(result) >= 200:
                                        self.allHostObjectList.remove(i)
                                    result = host.createHost(self.apiToken)
                                    if int(result) <= 299 and int(result) >= 200:
                                        self.allHostObjectList.append([host.getName(), host.getUUID(
                                        ), host.getValue(), host.getType(), host.getDescription()])
                                else:
                                    print("Condition 1.2.2: Skipped this host.")

                    print(flag_host)
                    if flag_host == True:
                        print("Condition 2", host.getName())
                        result = host.createHost(self.apiToken)
                        if int(result) <= 299 and int(result) >= 200:
                            self.allHostObjectList.append([host.getName(), host.getUUID(
                            ), host.getValue(), host.getType(), host.getDescription()])
                        print(result)

            case "network":
                for network in self.networkObjectList:
                    flag_network = True
                    for i in self.allNetworkObjectList:

                        if i[0] == network.getName():
                            flag_network = False
                            print("1: ", flag_network)
                            print(i[0], "Condition 1")
                            # print("True for ", network.getName(), "id: ", i[1])
                            if ((i[0] == network.getName()) and (i[2] == network.getValue())):
                                print(
                                    "Exactly same object so no need to delete. Condition 1.1 ", i[0])
                                flag_network = False
                            elif ((i[0] == network.getName()) and (i[2] != network.getValue())):
                                print(
                                    i[0], i[2], "Condition 1.2: There exists an object with x 4dwwwwwwwwwwwwwwwwwwwwwwvthe same name. Do you want to delete the existing object? Please answer Y/N: ")
                                ans = str(input())
                                if ans == 'Y':
                                    print("Condition 1.2.1")
                                    result = self.deleteNetwork(i[1])
                                    if int(result) <= 299 and int(result) >= 200:
                                        self.allNetworkObjectList.remove(i)

                                    result = network.createNetwork(
                                        self.apiToken)
                                    if int(result) <= 299 and int(result) >= 200:
                                        self.allNetworkObjectList.append([network.getName(), network.getUUID(
                                        ), network.getValue(), network.getType(), network.getDescription()])

                                    print("result crete network: ", result)
                                    print("Name for: ", network.getName(),
                                          " Id: ", network.getUUID())
                                else:
                                    print(
                                        "Condition 1.2.2: Skipped this network.")

                    print(flag_network)
                    if flag_network == True:
                        print("Condition 2", network.getName())
                        result = network.createNetwork(self.apiToken)
                        if int(result) <= 299 and int(result) >= 200:
                            self.allNetworkObjectList.append([network.getName(), network.getUUID(
                            ), network.getValue(), network.getType(), network.getDescription()])
                        print(result)
                        print("Name for: ", network.getName(),
                              " Id: ", network.getUUID())

            case "url":
                for url in self.URLObjectList:
                    flag_url = True
                    for i in self.allUrlObjectList:

                        if i[0] == url.getName():
                            flag_url = False
                            print("1: ", flag_url)
                            print(i[0], "Condition 1")
                            # print("True for ", network.getName(), "id: ", i[1])
                            if ((i[0] == url.getName()) and (i[2] == url.getValue())):
                                print(
                                    "Exactly same object so no need to delete. Condition 1.1 ", i[0])
                                flag_url = False
                            elif ((i[0] == url.getName()) and (i[2] != url.getValue())):
                                print(i[0], i[2],
                                      "Condition 1.2: There exists an object with the same name. Do you want to delete the existing object? Please answer Y/N: ")
                                ans = str(input())
                                if ans == 'Y':
                                    print("Condition 1.2.1")
                                    result = self.deleteUrls(i[1])
                                    if int(result) <= 299 and int(result) >= 200:
                                        self.allUrlObjectList.remove(i)
                                    result = url.createURL(self.apiToken)
                                    if int(result) <= 299 and int(result) >= 200:
                                        self.allUrlObjectList.append([url.getName(), url.getUUID(
                                        ), url.getValue(), url.getType(), url.getDescription()])
                                    print("result crete url: ", result)
                                    print("Name for: ", url.getName(),
                                          " Id: ", url.getUUID())
                                else:
                                    print("Condition 1.2.2: Skipped this url.")

                    print(flag_url)
                    if flag_url == True:
                        print("Condition 2", url.getName())
                        result = url.createURL(self.apiToken)
                        if int(result) <= 299 and int(result) >= 200:
                            self.allUrlObjectList.append([url.getName(), url.getUUID(
                            ), url.getValue(), url.getType(), url.getDescription()])
                        print(result)
                        print("Name for: ", url.getName(),
                              " Id: ", url.getUUID())

            case "fqdn":
                for fqdn in self.FQDNObjectList:
                    result = fqdn.createFQDN(self.apiToken)

                    if int(result) > 399:
                        return result

            case _:
                return None

    def __getSecurityZones(self):

        url = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, self.securityZoneLocation, id)

        securityZones = requests.get(
            url=url,
            headers=self.authHeader,
            verify=False
        )

        securityZones = securityZones.json()['items']

        returnList = []

        for zone in securityZones:
            del zone['links']
            returnList.append(SecurityZones.SecurityZoneObject(
                zone['name'], zone['id']))

        return returnList

    def __getPortObjects(self):

        url = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, self.portLocation)

        ports = requests.get(
            url=url,
            headers=self.authHeader,
            verify=False
        )

        ports = ports.json()['items']
        returnList = []

        for port in ports:
            del port['links']

            returnList.append(Port.PortObject(port['name'], port['id']))

        return returnList

    def __getFilePolicies(self):

        url = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, self.filePolicyLocation)

        filePolicies = requests.get(
            url=url,
            headers=self.authHeader,
            verify=False
        )

        filePolicies = filePolicies.json()['items']
        returnList = []

        for fp in filePolicies:
            del fp['links']

            returnList.append(
                FilePolicy.FilePolicyObject(fp['name'], fp['id']))

        return returnList

    def __getURLCategories(self):

        url = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, self.urlCategoryLocation)

        urlCategories = requests.get(
            url=url,
            headers=self.authHeader,
            verify=False
        )

        urlCategories = urlCategories.json()['items']
        returnList = []

        for cat in urlCategories:
            del cat['links']

            returnList.append(
                URLCategory.URLCategoryObject(cat['name'], cat['id']))
            # print("Name: ", cat['name'], " Id: ", cat['id'])

        return returnList

    def __getApplications(self):

        url = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, self.applicationLocation)

        applications = requests.get(
            url=url,
            headers=self.authHeader,
            verify=False
        )

        applications = applications.json()['items']
        returnList = []

        for cat in applications:
            del cat['links']

            returnList.append(
                Application.ApplicationObject(cat['name'], cat['id']))
            # print("A Name: ", cat['name'], " A Id: ", cat['id'])

        return returnList

    def __getAllNetworks(self):

        url = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, self.networkLocation)

        networks = requests.get(
            url=url,
            headers=self.authHeader,
            verify=False
        )

        networks = networks.json()['items']
        returnList = []

        for cat in networks:
            del cat['links']

            newURL = url + \
                     cat['id']

            network = requests.get(
                url=newURL,
                headers=self.authHeader,
                verify=False
           )

            network = network.json()
            returnList.append([network['name'], network['id'],
                              network['value'], network['type'], network['description']])

        return returnList

    def __getAllUrls(self):
        url = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, self.urlLocation)

        networks = requests.get(
            url=url,
            headers=self.authHeader,
            verify=False
        )

        urls = networks.json()['items']
        returnList = []

        for cat in urls:
            del cat['links']

            newURL = url + \
                     cat['id']

            network = requests.get(
                url=newURL,
                headers=self.authHeader,
                verify=False
            )

            network = network.json()
            returnList.append(
                [network['name'], network['id'], network['url'], network['type'], network['description']])
        return returnList

    def __getAllHosts(self):
        url = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, self.hostLocation)

        hosts = requests.get(
            url=url,
            headers=self.authHeader,
            verify=False
        )

        hosts = hosts.json()['items']
        returnList = []

        for cat in hosts:
            del cat['links']

            newURL = url + \
                     cat['id']

            host = requests.get(
                url=newURL,
                headers=self.authHeader,
                verify=False
            )

            host = host.json()
            returnList.append(
                [host['name'], host['id'], host['value'], host['type'], host['description']])

        return returnList

    def __getAllGroups(self):
        url = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, self.networkGroupLocation)
        
        hosts = requests.get(
            url=url,
            headers=self.authHeader,
            verify=False
        )

        hosts = hosts.json()['items']
        returnList = []

        for cat in hosts:
            del cat['links']

            newURL = url + \
                     cat['id']

            host = requests.get(
                url=newURL,
                headers=self.authHeader,
                verify=False
            )

            # host = host.json()['objects']
            if 'objects' in host.json().keys():
                returnList.append(
                    [cat['name'], cat['id'], "objects", cat['type'], host.json()['objects']])
            elif 'literals' in host.json().keys():
                returnList.append(
                    [cat['name'], cat['id'], "literals", cat['type'], host.json()['literals']])

        hosts = requests.get(
            url=url,
            headers=self.authHeader,
            verify=False
        )

        hosts = hosts.json()['items']

        for cat in hosts:
            del cat['links']

            newURL = url + \
                     cat['id']

            host = requests.get(
                url=newURL,
                headers=self.authHeaders,
                verify=False
            )

            # host = host.json()['objects']
            if 'objects' in host.json().keys():
                returnList.append(
                    [cat['name'], cat['id'], 'objects', cat['type'], host.json()['objects']])
            elif 'literals' in host.json().keys():
                returnList.append(
                    [cat['name'], cat['id'], 'literals', cat['type'], host.json()['literals']])

        return returnList

    def deleteNetwork(self, id):
        url = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, self.networkLocation, id)
        networks = requests.delete(
            url=url,
            headers=self.authHeader,
            verify=False
        )

        return networks.status_code

    def deleteUrls(self, id):
        url = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, self.urlLocation, id)
        networks = requests.delete(
            url=url,
            headers=self.authHeader,
            verify=False
        )

        return networks.status_code

    def deleteHosts(self, id):
        url = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, self.hostLocation, id)
        networks = requests.delete(
            url=url,
            headers=self.authHeader,
            verify=False
        )

        return networks.status_code

    def createAccessRule(self, csvRow):
        
        policyObject = AccessPolicy.AccessPolicyObject('e276abec-e0f2-11e3-8169-6d9ed49b625f', '005056B6-DCA2-0ed3-0000-004294973677', self.securityZoneObjectList, self.allNetworkObjectList,
                                                       self.portObjectList, self.filePolicyObjectList, self.urlCategoryObjectList, self.allUrlObjectList, self.allGroupsList, self.applicationObjectList, self.fmcIP)
        response = policyObject.createPolicy(self.apiToken, csvRow)

        return response





