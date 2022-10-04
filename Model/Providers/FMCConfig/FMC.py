import requests
from requests.auth import HTTPBasicAuth
from Model.DataObjects import Host, Network, Port, FQDN, ObjectGroup, Application, AllGroupObjects, AllNetworksObject
from Model.DataObjects.GroupTypeEnum import GroupTypeEnum
from Model.Providers.Provider import Provider, buildUrlForResource, buildUrlForResourceWithId
from Model.RulesObjects import AccessPolicy, ApplicationCategory, ApplicationRisk, ApplicationType, FilePolicy, \
    SecurityZones, URL, URLCategory
from Model.Utilities.LoggingUtils import Logger_GetLogger
from Model.Utilities.StringUtils import checkYesNoResponse, checkValidGroupType
from Model.DataObjects.YesNoEnum import YesNoEnum


class FMC(Provider):

    def __init__(self, ipAddress, username, password):
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

        self.apiToken = self.requestToken(username, password)

        self.authHeader = {"X-auth-access-token": self.apiToken}

        self.hostObjectList = []
        self.networkObjectList = []
        self.objectGroupList = []
        self.URLObjectList = []
        self.FQDNObjectList = []

        self.supportedObjectList = ["host","network","url","fqdn"]

        self.domainLocation = "/api/fmc_config/v1/domain/"

        self.networkLocation = "/object/networks"
        self.networkGroupLocation = "/object/networkgroups"
        self.urlLocation = "/object/urls"
        self.urlGroupLocation = "/object/urlgroups"
        self.securityZoneLocation = "/object/securityzones"
        self.portLocation = "/object/ports"
        self.urlCategoryLocation = "/object/urlcategories"
        self.applicationLocation = "/object/applications"
        self.hostLocation = "/object/hosts"
        self.fqdnLocation = "/object/fqdns"

        self.filePolicyLocation = "/policy/filepolicies"
        self.accessPolicyLocation = "/policy/accesspolicies"

        self.portObjectList = self.__getPortObjects()
        self.securityZoneObjectList = self.__getSecurityZones()
        self.filePolicyObjectList = self.__getFilePolicies()
        self.urlCategoryObjectList = self.__getURLCategories()
        self.applicationObjectList = self.__getApplications()
        # self.allNetworkGroupObjectList = self.__getAllNetworkGroups()
        self.allNetworkObjectList = self.__getAllNetworks()
        self.allGroupsList = self.__getAllGroups()
        # self.allUrlGroupList = self.__getAllUrlGroups()
        self.allUrlObjectList = self.__getAllUrls()
        self.allHostObjectList = self.__getAllHosts()
        self.allFQDNObjects = self.__getAllFQDNs()

        return None

    def requestToken(self, username, password):
        """
        We will need to extract these username/password values and either read them from user input or a security key file
        Can we pull the domain ID from this auth request and set it by default?
        """
        url = 'https://' + self.fmcIP + '/api/fmc_platform/v1/auth/generatetoken'
        response = requests.post(
            url='https://10.255.20.10/api/fmc_platform/v1/auth/generatetoken',
            auth=HTTPBasicAuth(username, password),
            data={},
            verify=False)

        if response.headers['DOMAIN_UUID']:
            self.domainId = response.headers['DOMAIN_UUID']
            self.logger.info("Domain Id found and set")
            pass

        self.logger.info("Auth token found and set")
        return response.headers['X-auth-access-token']

    def CheckAndAddGroup(self, groupName: str):
        groupExists = ObjectGroup.GroupObject.checkIfGroupExists(
            groupName, self.fmcIP, self.domainLocation, self.domainId,
            self.apiToken)
        createGroupFlag = None
        statusCode = None
        groupType = None

        if groupExists == False:
            while not checkYesNoResponse(createGroupFlag):
                self.logger.info("The group: " + groupName +
                                 " was not found, create this group? (Yes/No)")
                createGroupFlag = str(input())

            if createGroupFlag == YesNoEnum.YES.value:

                while not checkValidGroupType(groupType):
                    self.logger.info(
                        "Select the Group Type for the new group:")
                    self.logger.info(GroupTypeEnum.list())
                    groupType = str(input())

                statusCode = ObjectGroup.GroupObject.createNewGroup(
                    groupName, groupType, self.fmcIP, self.domainLocation,
                    self.domainId, self.apiToken)
                self.logger.info("The group:" + groupName +
                                 " was posted to FMC. {Status Code: " +
                                 str(statusCode) + "Type: " + groupType + "}")
                pass
            pass
        else:
            self.logger.info("Host Group Found. {Group Name:" + groupName +
                             "}")

    def __addHost(self, name: str, value: str, description='', group=''):
        """
        Creates a Host object with the FMC constructor and adds it to the Host Object List

        Args:
            name (str): The name of the host to be added
            value (str): The value for the host object
            description (str, optional): The description to be added to the Host object. Defaults to ''.
            group (str, optional): The name of a Host Group in FMC to add. Defaults to ''.

        Returns:
            None: The Host object is appended to the Host Object List
        """

        #if group:
        #    self.CheckAndAddGroup(group)

        hostObj = Host.HostObject.FMCHost(self, name, value, description,
                                          group)
        self.logger.info("Host added. {Name: " + name + ", Value: " + group +
                         "}")
        return self.hostObjectList.append(hostObj)

    def __addNetwork(self, name: str, value: str, description='', group=''):

        #if group:
        #    self.CheckAndAddGroup(group)

        networkObj = Network.NetworkObject.FMCNetwork(self, name, value,
                                                      description, group)
        self.logger.info("Network added. {Name: " + name + ", Value: " +
                         value + "}")
        return self.networkObjectList.append(networkObj)

    def __addURL(self, name, url, description='', group=''):

        #if group:
        #    self.CheckAndAddGroup(group)

        urlObj = URL.URLObject.FMCUrlObject(self, name, url, description,
                                            group)
        self.logger.info("URL added. {Name: " + name + ", Value: " + url + "}")
        return self.URLObjectList.append(urlObj)

    def __addFQDN(self, name, value, description='', group=''):

        #if group:
        #    self.CheckAndAddGroup(group)

        fqdnObj = FQDN.FQDNObject.FMCFQDN(self, name, value, description,
                                          group)
        self.logger.info("FQDN added. {Name: " + name + ", Value: " + value +
                         "}")
        return self.FQDNObjectList.append(fqdnObj)

    def __createGroupMembershipLists(self, type: str):

        groupDict = {}

        if type == 'host':
            for host in self.hostObjectList:

                hostName = host.getName()
                hostID = host.getUUID()
                groupName = host.getGroupMembership()

                if groupName not in groupDict:  # If group name is not in the dictionary then we add the group name and associate an empty list with the group and append the values in it
                    self.logger.info(
                        "Group Not Found, Added to as new List. {Host: " +
                        hostName + ", GroupName: " + groupName + "}")
                    groupDict[groupName] = []
                    groupDict[groupName].append({
                        'type':
                        ObjectTypeEnum.HOST.value.capitalize(),
                        'id':
                        hostID,
                        'name':
                        hostName
                    })
                else:
                    self.logger.info("Group Discovered and Added. {Host: " +
                                     hostName + ", GroupName: " + groupName +
                                     "}")
                    groupDict[groupName].append({
                        'type':
                        ObjectTypeEnum.HOST.value.capitalize(),
                        'id':
                        hostID,
                        'name':
                        hostName
                    })
        elif type == 'network':
            for network in self.networkObjectList:

                networkName = network.getName()
                networkID = network.getUUID()
                groupName = network.getGroupMembership()

                if groupName not in groupDict:
                    self.logger.info(
                        "Group Not Found, Added as new to List. {Network: " +
                        networkName + ", GroupName: " + groupName + "}")
                    groupDict[groupName] = []
                    groupDict[groupName].append({
                        'type':
                        ObjectTypeEnum.NETWORK.value.capitalize(),
                        'id':
                        networkID,
                        'name':
                        networkName
                    })
                else:
                    self.logger.info("Group Discovered and Added. {Network: " +
                                     networkName + ", GroupName: " +
                                     groupName + "}")
                    groupDict[groupName].append({
                        'type':
                        ObjectTypeEnum.NETWORK.value.capitalize(),
                        'id':
                        networkID,
                        'name':
                        networkName
                    })

        elif type == 'url':
            for url in self.URLObjectList:

                urlName = url.getName()
                urlID = url.getUUID()
                groupName = url.getGroupMembership()

                if groupName not in groupDict:
                    self.logger.info(
                        "Group Not Found, Added as new to List. {URL: " +
                        urlName + ", GroupName: " + groupName + "}")
                    groupDict[groupName] = []
                    groupDict[groupName].append({
                        'type':
                        ObjectTypeEnum.URL.value.capitalize(),
                        'id':
                        urlID,
                        'name':
                        urlName
                    })

                else:
                    self.logger.info("Group Discovered and Added. {URL: " +
                                     urlName + ", GroupName: " + groupName +
                                     "}")
                    groupDict[groupName].append({
                        'type':
                        ObjectTypeEnum.URL.value.capitalize(),
                        'id':
                        urlID,
                        'name':
                        urlName
                    })
        elif type == 'fqdn':
            for fqdn in self.FQDNObjectList:

                fqdnName = fqdn.getName()
                fqdnID = fqdn.getID()
                groupName = fqdn.getGroupMembership()

                if groupName not in groupDict:  # If group name is not in the dictionary then we add the group name and associate an empty list with the group and append the values in it
                    self.logger.info(
                        "Group Not Found, Added to as new List. {Host: " +
                        fqdnName + ", GroupName: " + groupName + "}")
                    groupDict[groupName] = []
                    groupDict[groupName].append({
                        'type': ObjectTypeEnum.FQDN.value,
                        'id': fqdnID,
                        'name': fqdnName
                    })
                else:
                    self.logger.info("Group Discovered and Added. {Host: " +
                                     fqdnName + ", GroupName: " + groupName +
                                     "}")
                    groupDict[groupName].append({
                        'type': ObjectTypeEnum.FQDN.value,
                        'id': fqdnID,
                        'name': fqdnName
                    })

        self.logger.info("Group Membership Lists Resolved. {Type: " + type +
                         "}")

        return groupDict

    def deleteGroup(self, id, type):
        groupLocation = self.networkGroupLocation if type == "network" else self.urlGroupLocation

        url = buildUrlForResourceWithId(self.fmcIP, self.domainLocation,
                                        self.domainId, groupLocation, id)

        self.logger.info("Deleting group. {Group Type: " + groupLocation + "}")

        networks = requests.delete(url=url,
                                   headers=self.authHeader,
                                   verify=False)

        self.logger.info("Group deleted. {Id: " + id + ", Type: " + type +
                         ", Status Code: " + str(networks.status_code) + "}")
        return networks.status_code

    def appendToGroup(self, groupId, groupType, objectName, objectId,
                      objectType):
        groupLocation = self.networkGroupLocation if groupType == "network" or "NetworkGroup" else self.urlGroupLocation

        url = buildUrlForResourceWithId(self.fmcIP, self.domainLocation,
                                        self.domainId, groupLocation, groupId)

        group = requests.get(url=url, headers=self.authHeader, verify=False)

        members = group.json()['objects']
        idgrp = group.json()['id']
        namegrp = group.json()['name']
        typegrp = group.json()['type']

        newObject = {}
        newObject["name"] = objectName
        newObject["id"] = objectId
        newObject["type"] = objectType

        members.append(newObject)

        group = requests.get(url=url, headers=self.authHeader, verify=False)

        payload = {
            "objects": members,
            "id": idgrp,
            "name": namegrp,
            "type": typegrp
        }
        response = requests.put(url=url,
                                headers=self.authHeader,
                                data=payload.json(),
                                verify=False)

        return response.status_code

    def createGroups(self, type):

        groupDict = self.__createGroupMembershipLists(type)

        for group in groupDict:
            if type == 'host' or type == 'fqdn':
                type = 'network'

            objGroup = ObjectGroup.GroupObject(self.domainId, group, type,
                                               groupDict[group], self.fmcIP)

            for i in self.allGroupsList:
                if i[0] == objGroup.getName():
                    self.allGroupsList.append([
                        objGroup.getName(),
                        objGroup.getUUID(), 'objects', i[3], groupDict[group]
                    ])
                    
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
            self.__addNetwork(name, value, description, group)

        elif type == 'url':
            self.__addURL(name, value, description, group)

        elif type == 'fqdn':
            self.__addFQDN(name, value, description, group)

        else:
            return "Object type not configured"

    def getObjectList(self, objectType: str):

        if objectType == ObjectTypeEnum.HOST:
            return self.hostObjectList

        if objectType == ObjectTypeEnum.NETWORK:
            return self.networkObjectList

        if objectType == ObjectTypeEnum.URL:
            return self.URLObjectList

        if objectType == ObjectTypeEnum.FQDN:
            return self.FQDNObjectList

        if objectType == ObjectTypeEnum.PORT:
            return self.portObjectList

        if objectType == ObjectTypeEnum.SECURITYZONE:
            return self.securityZoneObjectList

        return None

    def applyObjectList(self, listType):

        if listType == ObjectTypeEnum.HOST:
            for host in self.hostObjectList:
                flag_host = True
                for i in self.allHostObjectList:

                    if i[0] == host.getName():
                        flag_host = False
                        if ((i[0] == host.getName())
                                and (i[2] == host.getValue())):
                            self.logger.info(
                                "Host found with same name and value. {Host: "
                                + str(i[0]) + "}")
                            flag_network = False
                        else:
                            print("Condition 1.2.2: Skipped this host.")

                if flag_host == True:
                    result = host.createFMCHost(self.authHeader)
                    if int(result) <= 299 and int(result) >= 200:
                        self.logger.info(
                            "Host created. {Host: " + host.getName() + "}", )
                        self.allHostObjectList.append([
                            host.getName(),
                            host.getUUID(),
                            host.getValue(),
                            host.getType(),
                            host.getDescription()
                        ])
                    print(result)
            pass

        if listType == ObjectTypeEnum.NETWORK:
            for network in self.networkObjectList:
                flag_network = True
                for i in self.allNetworkObjectList:

                    if i[0] == network.getName():
                        flag_network = False
                        print("1: ", flag_network)
                        print(i[0], "Condition 1")
                        print("True for ", network.getGroupMembership(),
                              "id: ", i)
                        if ((i[0] == network.getName())
                                and (i[2] == network.getValue())):
                            print(
                                "Exactly same object so no need to delete. Condition 1.1 ",
                                i[0])
                            flag_network = False
                        elif ((i[0] == network.getName())
                              and (i[2] != network.getValue())):
                            print(
                                i[0], i[2],
                                "Condition 1.2: There exists an object with the same name. Do you want to delete the existing object? Please answer Y/N: "
                            )
                            ans = str(input())
                            if ans == 'Y':
                                print("Condition 1.2.1")
                                result = self.deleteNetwork(i[1])
                                if int(result) <= 299 and int(result) >= 200:
                                    self.allNetworkObjectList.remove(i)

                                result = network.createNetwork(self.authHeader)
                                if int(result) <= 299 and int(result) >= 200:
                                    self.allNetworkObjectList.append([
                                        network.getName(),
                                        network.getUUID(),
                                        network.getValue(),
                                        network.getType(),
                                        network.getDescription()
                                    ])

                                print("result crete network: ", result)
                                print("Name for: ", network.getName(), " Id: ",
                                      network.getUUID())
                            else:
                                print("Condition 1.2.2: Skipped this network.")

                print(flag_network)
                if flag_network == True:
                    print("Condition 2", network.getName())
                    authHeader = {"X-auth-access-token": self.apiToken}
                    result = network.createNetwork(authHeader)
                    if int(result) <= 299 and int(result) >= 200:
                        self.allNetworkObjectList.append([
                            network.getName(),
                            network.getUUID(),
                            network.getValue(),
                            network.getType(),
                            network.getDescription()
                        ])
                    print(result)
                    print("Name for: ", network.getName(), " Id: ",
                          network.getUUID())
            pass

        if listType == ObjectTypeEnum.URL:
            for url in self.URLObjectList:
                flag_url = True
                for i in self.allUrlObjectList:

                    if i[0] == url.getName():
                        flag_url = False
                        print("1: ", flag_url)
                        print(i[0], "Condition 1")
                        # print("True for ", network.getName(), "id: ", i[1])
                        if ((i[0] == url.getName())
                                and (i[2] == url.getValue())):
                            print(
                                "Exactly same object so no need to delete. Condition 1.1 ",
                                i[0])
                            flag_url = False
                        else:
                            print("Condition 1.2.2: Skipped this url.")

                print(flag_url)
                if flag_url == True:
                    print("Condition 2", url.getName())
                    result = url.createURL(self.authHeader)
                    if int(result) <= 299 and int(result) >= 200:
                        self.allUrlObjectList.append([
                            url.getName(),
                            url.getUUID(),
                            url.getValue(),
                            url.getType(),
                            url.getDescription()
                        ])
                    print(result)
                    print("Name for: ", url.getName(), " Id: ", url.getUUID())
            pass

        if listType == ObjectTypeEnum.FQDN:
            for fqdn in self.FQDNObjectList:
                result = fqdn.createFQDN(self.authHeader)
                if int(result) > 399:
                    return result
            pass

        return None

    def __getSecurityZones(self):

        url = buildUrlForResource(self.fmcIP, self.domainLocation,
                                  self.domainId, self.securityZoneLocation)

        securityZones = requests.get(url=url,
                                     headers=self.authHeader,
                                     verify=False)

        securityZones = securityZones.json()['items']

        returnList = []

        for zone in securityZones:
            del zone['links']
            returnList.append(
                SecurityZones.SecurityZoneObject(zone['name'], zone['id']))

        return returnList

    def __getPortObjects(self):

        portCount = 0
        url = buildUrlForResource(self.fmcIP, self.domainLocation,
                                  self.domainId, self.portLocation)

        ports = requests.get(url=url, headers=self.authHeader, verify=False)

        ports = ports.json()['items']
        returnList = []

        for port in ports:
            del port['links']
            portCount + 1
            returnList.append(Port.PortObject(port['name'], port['id']))

        self.logger.info("Port objects added to list. {Ports:" +
                         str(portCount) + "}")

        return returnList

    def __getFilePolicies(self):

        url = buildUrlForResource(self.fmcIP, self.domainLocation,
                                  self.domainId, self.filePolicyLocation)

        filePolicies = requests.get(url=url,
                                    headers=self.authHeader,
                                    verify=False)

        filePolicies = filePolicies.json()['items']
        returnList = []

        for fp in filePolicies:
            del fp['links']

            returnList.append(FilePolicy.FilePolicyObject(
                fp['name'], fp['id']))

        return returnList

    def __getURLCategories(self):

        url = buildUrlForResource(self.fmcIP, self.domainLocation,
                                  self.domainId, self.urlCategoryLocation)

        urlCategories = requests.get(url=url,
                                     headers=self.authHeader,
                                     verify=False)

        urlCategories = urlCategories.json()['items']
        returnList = []

        for cat in urlCategories:
            del cat['links']

            returnList.append(
                URLCategory.URLCategoryObject(cat['name'], cat['id']))
            # print("Name: ", cat['name'], " Id: ", cat['id'])

        return returnList

    def __getApplications(self):

        url = buildUrlForResource(self.fmcIP, self.domainLocation,
                                  self.domainId, self.applicationLocation)

        applications = requests.get(url=url,
                                    headers=self.authHeader,
                                    verify=False)

        applications = applications.json()['items']
        returnList = []

        for cat in applications:
            del cat['links']

            returnList.append(
                Application.ApplicationObject(cat['name'], cat['id']))
            # print("A Name: ", cat['name'], " A Id: ", cat['id'])

        return returnList

    def __getAllNetworks(self):

        url = buildUrlForResource(self.fmcIP, self.domainLocation,
                                  self.domainId, self.networkLocation)

        networks = requests.get(url=url, headers=self.authHeader, verify=False)

        networks = networks.json()['items']
        returnList = []

        for cat in networks:
            del cat['links']

            newUrl = buildUrlForResourceWithId(self.fmcIP, self.domainLocation,
                                               self.domainId,
                                               self.networkLocation, cat['id'])

            network = requests.get(url=newUrl,
                                   headers=self.authHeader,
                                   verify=False)

            network = network.json()

            if network and network["name"]:
                self.logger.info("Network retrieved. {Name: " +
                                 network['name'] + ", Value: " +
                                 network['value'] + "}")

            returnList.append([
                network['name'], network['id'], network['value'],
                network['type'], network['description']
            ])

        return returnList

    def __getAllUrls(self):
        url = buildUrlForResource(self.fmcIP, self.domainLocation,
                                  self.domainId, self.urlLocation)

        networks = requests.get(url=url, headers=self.authHeader, verify=False)

        urls = networks.json()['items']
        returnList = []

        for cat in urls:
            del cat['links']

            newURL = buildUrlForResourceWithId(self.fmcIP, self.domainLocation,
                                               self.domainId, self.urlLocation,
                                               cat['id'])

            network = requests.get(url=newURL,
                                   headers=self.authHeader,
                                   verify=False)

            network = network.json()
            returnList.append([
                network['name'], network['id'], network['url'],
                network['type'], network['description']
            ])
        return returnList

    def __getAllHosts(self):
        url = buildUrlForResource(self.fmcIP, self.domainLocation,
                                  self.domainId, self.hostLocation)

        hosts = requests.get(url=url, headers=self.authHeader, verify=False)

        hosts = hosts.json()['items']
        returnList = []

        for cat in hosts:
            del cat['links']

            newURL = buildUrlForResourceWithId(self.fmcIP, self.domainLocation,
                                               self.domainId,
                                               self.hostLocation, cat['id'])

            host = requests.get(url=newURL,
                                headers=self.authHeader,
                                verify=False)

            host = host.json()
            returnList.append([
                host['name'], host['id'], host['value'], host['type'],
                host['description']
            ])

        return returnList

    def __getAllFQDNs(self):
        url = buildUrlForResource(self.fmcIP, self.domainLocation,
                                  self.domainId, self.fqdnLocation)

        fqdn = requests.get(url=url, headers=self.authHeader, verify=False)

        print("FQDN all response: ", fqdn.json())

        fqdns = fqdn.json()['items']
        returnList = []

        for cat in fqdns:
            del cat['links']

            newURL = buildUrlForResourceWithId(self.fmcIP, self.domainLocation,
                                               self.domainId,
                                               self.fqdnLocation, cat['id'])

            fqdn = requests.get(url=newURL,
                                headers=self.authHeader,
                                verify=False)

            fqdn = fqdn.json()
            returnList.append([
                fqdn['name'], fqdn['id'], fqdn['value'], fqdn['type'],
                fqdn['description']
            ])

        return returnList

    def __getAllGroups(self):
        url = buildUrlForResource(self.fmcIP, self.domainLocation,
                                  self.domainId, self.networkGroupLocation)

        hosts = requests.get(url=url, headers=self.authHeader, verify=False)

        hosts = hosts.json()['items']
        returnList = []

        for cat in hosts:
            del cat['links']

            newUrl = buildUrlForResourceWithId(self.fmcIP, self.domainLocation,
                                               self.domainId,
                                               self.networkGroupLocation,
                                               cat['id'])

            host = requests.get(url=newUrl,
                                headers=self.authHeader,
                                verify=False)

            # host = host.json()['objects']
            if 'objects' in host.json().keys():
                returnList.append([
                    cat['name'], cat['id'], "objects", cat['type'],
                    host.json()['objects']
                ])
            elif 'literals' in host.json().keys():
                returnList.append([
                    cat['name'], cat['id'], "literals", cat['type'],
                    host.json()['literals']
                ])

        hosts = requests.get(url=url, headers=self.authHeader, verify=False)

        hosts = hosts.json()['items']

        for cat in hosts:
            del cat['links']

            newUrl = buildUrlForResourceWithId(self.fmcIP, self.domainLocation,
                                               self.domainId,
                                               self.networkGroupLocation,
                                               cat['id'])

            host = requests.get(url=newUrl,
                                headers=self.authHeader,
                                verify=False)

            # host = host.json()['objects']
            if 'objects' in host.json().keys():
                returnList.append([
                    cat['name'], cat['id'], 'objects', cat['type'],
                    host.json()['objects']
                ])
            elif 'literals' in host.json().keys():
                returnList.append([
                    cat['name'], cat['id'], 'literals', cat['type'],
                    host.json()['literals']
                ])

        return returnList

    def deleteNetwork(self, id):
        url = buildUrlForResourceWithId(self.fmcIP, self.domainLocation,
                                        self.domainId, self.networkLocation,
                                        id)
        networks = requests.delete(url=url,
                                   headers=self.authHeader,
                                   verify=False)

        return networks.status_code

    def deleteUrls(self, id):
        url = buildUrlForResourceWithId(self.fmcIP, self.domainLocation,
                                        self.domainId, self.urlLocation, id)
        networks = requests.delete(url=url,
                                   headers=self.authHeader,
                                   verify=False)

        return networks.status_code

    def deleteHosts(self, id):
        url = buildUrlForResourceWithId(self.fmcIP, self.domainLocation,
                                        self.domainId, self.hostLocation, id)

        networks = requests.delete(url=url,
                                   headers=self.authHeader,
                                   verify=False)

        return networks.status_code

    def deleteFQDNs(self, id):
        url = buildUrlForResourceWithId(self.fmcIP, self.domainLocation,
                                        self.domainId, self.fqdnLocation, id)
        networks = requests.delete(url=url,
                                   headers=self.authHeader,
                                   verify=False)

        return networks.status_code

    def mergeAllNetworkTypes(self):
        networks = self.allNetworkObjectList
        hosts = self.allHostObjectList

        for i in hosts:
            networks.append(i)

        for i in self.allFQDNObjects:
            networks.append(i)

        return networks

    def createAccessRule(self, csvRow):
        allNetworks = self.mergeAllNetworkTypes()

        policyObject = AccessPolicy.AccessPolicyObject.FMCAccessPolicyObject(
            self, '005056B6-DCA2-0ed3-0000-004294973677',
            self.securityZoneObjectList, allNetworks, self.portObjectList,
            self.filePolicyObjectList, self.urlCategoryObjectList,
            self.allUrlObjectList, self.allGroupsList,
            self.applicationObjectList)

        response = policyObject.createPolicy(self.apiToken, csvRow)

        return response

    def createNATRules(self, csvRow):

        allNetworks = self.mergeAllNetworkTypes()

        policyObject = AccessPolicy.AccessPolicyObject.FMCAccessPolicyObject(
            self, '005056B6-DCA2-0ed3-0000-004294973677',
            self.securityZoneObjectList, allNetworks, self.portObjectList,
            self.filePolicyObjectList, self.urlCategoryObjectList,
            self.allUrlObjectList, self.allGroupsList,
            self.applicationObjectList)

        response = policyObject.createNATRules(self.apiToken, csvRow)

        return response
