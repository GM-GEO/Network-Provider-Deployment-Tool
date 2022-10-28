import requests
from requests.auth import HTTPBasicAuth
from Model.DataObjects import Host, Network, Port, FQDN, ObjectGroup, Application, AllGroupObjects, AllNetworksObject, TCP, UDP, Range
from Model.DataObjects.Enums.GroupTypeEnum import GroupTypeEnum
from Model.Providers.Provider import Provider, buildUrlForResource, buildUrlForResourceWithId
from Model.RulesObjects import AccessPolicy, ApplicationCategory, ApplicationRisk, ApplicationType, FilePolicy, SecurityZones, URL, URLCategory
from Model.Utilities.LoggingUtils import Logger_GetLogger
from Model.Utilities.StringUtils import checkYesNoResponse, checkValidGroupType
from Model.DataObjects.Enums.YesNoEnum import YesNoEnum


class FMC(Provider):
    def __init__(self, ipAddress, username, password):
        """Creates the FMC provider with the lists of objects and resource locations

        Args:
            ipAddress (string): The IP Address of the provider

        Notes:
            The domainId attribute is set as part of the self.requestToken() call made
            by the self.apiToken instantiation.

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
        self.portObjectList = []
        self.tcpObjectList = []
        self.udpObjectList = []
        self.rangeObjectList = []

        self.supportedObjectList = ["host", "network", "url", "fqdn"]

        self.domainLocation = "/api/fmc_config/v1/domain/"

        self.networkLocation = "/object/networks"
        self.networkGroupLocation = "/object/networkgroups"
        self.urlLocation = "/object/urls"
        self.urlGroupLocation = "/object/urlgroups"
        self.securityZoneLocation = "/object/securityzones"
        self.portLocation = "/object/protocolportobjects"
        self.urlCategoryLocation = "/object/urlcategories"
        self.applicationLocation = "/object/applications"
        self.hostLocation = "/object/hosts"
        self.fqdnLocation = "/object/fqdns"
        self.rangeLocation = "/object/ranges"

        self.filePolicyLocation = "/policy/filepolicies"
        self.accessPolicyLocation = "/policy/accesspolicies"
        self.natPolicyLocation = "/policy/ftdnatpolicies"

        self.natRules = "/Policies/NatRules"


        self.allPortObjectList = self.__getAllPortObjects()
        self.allRangeObjects = self.__getAllRanges()
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
        self.allNetworkGroups = self.__getNetworkGroups()

        return None

    def requestToken(self, username, password):
        """
        Retrieves the domain UUID and authentication token
        :param username: username for authentication
        :param password: password for authentication
        :return: authentication token
        """
        """
        We will need to extract these username/password values and either read them from user input or a security key file
        """
        url = 'https://' + self.fmcIP + '/api/fmc_platform/v1/auth/generatetoken'
        response = requests.post(
                url='https://10.255.20.10/api/fmc_platform/v1/auth/generatetoken',
                auth=HTTPBasicAuth(username, password),
                data={},
                verify=False
            )

        if response.headers['DOMAIN_UUID']:
            self.domainId = response.headers['DOMAIN_UUID']
            self.logger.info("Domain Id found and set")
            pass

        self.logger.info("Auth token found and set")
        return response.headers['X-auth-access-token']

    def CheckAndAddGroup(self, groupName: str):
        groupExists = ObjectGroup.GroupObject.checkIfGroupExists(groupName, self.fmcIP, self.domainLocation, self.domainId, self.apiToken)
        createGroupFlag = None
        statusCode = None
        groupType = None

        if groupExists == False:
            while not checkYesNoResponse(createGroupFlag):
                self.logger.info("The group: " + groupName + " was not found, create this group? (Yes/No)")
                createGroupFlag = str(input())

            if createGroupFlag == YesNoEnum.YES.value:

                while not checkValidGroupType(groupType):
                    self.logger.info("Select the Group Type for the new group:")
                    self.logger.info(GroupTypeEnum.list())
                    groupType = str(input())

                statusCode = ObjectGroup.GroupObject.createNewGroup(groupName, groupType, self.fmcIP, self.domainLocation, self.domainId, self.apiToken)
                self.logger.info("The group:" + groupName + " was posted to FMC. {Status Code: " + str(statusCode) + "Type: " + groupType + "}")
                pass
            pass
        else :
            self.logger.info("Host Group Found. {Group Name:" + groupName +"}")
        

    def __addHost(self, name: str, value: str, description='', group=''):
        """
        Creates a Host object with the FMC constructor and adds it to the Host Object List

        Args:
            name (str): The name of the host to be added
            value (str): The value for the host object
            description (str, optional): The description to be added to the Host object. Defaults to ''.
            group (str, optional): The name of a Network Group in FMC to add. Defaults to ''.

        Returns:
            None: The Host object is appended to the Host Object List
        """

        #if group:
        #    self.CheckAndAddGroup(group)
        
        hostObj = Host.HostObject.FMCHost(self, name, value, description, group)    
        # self.logger.info("Host added. {Name: " + name + ", Value: " + group + "}")
        return self.hostObjectList.append(hostObj)

    def __addNetwork(self, name: str, value: str, description='', group=''):
        """
        Creates a Network object with the FMC constructor and adds it to the Network Object List.
        :param name: Name of the network to be added.
        :param value: The value of the network.
        :param description: Description of the network. It is optional and defaults to ''.
        :param group: The name of the Network object group which the network object should be added to.
        :return:  None: The Network object is appended to the Network Object List
        """
        networkObj = Network.NetworkObject.FMCNetwork(self, name, value, description, group)
        self.logger.info("Network added. {Name: " + name + ", Value: " + value + "}")
        return self.networkObjectList.append(networkObj)

    def __addURL(self, name, url, description='', group=''):
        """
            Creates a Network object with the FMC constructor and adds it to the URL Object List.
            :param name: Name of the URL to be added.
            :param url: The value of the URL.
            :param description: Description of the network. It is optional and defaults to ''.
            :param group: The name of the URL object group in which the URL should be added.
            :return:  None: The URL object is appended to the URL Object list.
        """
        urlObj = URL.URLObject.FMCUrlObject(self, name, url, description, group)
        self.logger.info("URL added. {Name: " + name + ", Value: " + url + "}")
        return self.URLObjectList.append(urlObj)

    def __addFQDN(self, name, value, description='', group=''):
        """
            Creates a FQDN object with the FMC constructor and adds it to the FQDN Object list.
            :param name: Name of the FQDN to be added.
            :param value: The value of FQDN.
            :param description: Description of the FQDN being added. It is optional and defaults to ''.
            :param group: The name of the FQDN object group in which the FQDN should be added.
            :return:  None: The FQDN object is appended to the FQDN Object list.
        """

        fqdnObj = FQDN.FQDNObject.FMCFQDN(self, name, value, description, group)
        self.logger.info("FQDN added. {Name: " + name + ", Value: " + value + "}")
        return self.FQDNObjectList.append(fqdnObj)
    def __addRange(self, name, value, description='', group=''):
        rangeObj = Range.RangeObject.FMCRange(self, name, value, description, group)
        self.logger.info("Range added. {Name: " + name + ", Value: " + value + "}")
        return self.rangeObjectList.append(rangeObj)

    def __addTCP(self, name, value, description='', group=''):

        tcpObj = TCP.TCPObject.FMCTCP(self, name, value, description)
        self.logger.info("TCP added. {Name: " + name + ", Value: " + value + "}")
        return self.tcpObjectList.append(tcpObj)

    def __addUDP(self, name, value, description='', group=''):

        udpObj = UDP.UDPObject.FMCUDP(self, name, value, description, group)
        self.logger.info("UDP added. {Name: " + name + ", Value: " + value + "}")
        return self.udpObjectList.append(udpObj)


    def createGroupMembershipLists(self, type):
        """
        Makes the list of groups and the objects which are to be added in the respective groups.
        :param type: The type of the groups being created. Type 'url' will result in UrlGroups, and hosts,
                     FQDNs, and Networks will result in NetworkGroups
        :return: The dictionary containing all the group names and their constituent objects.
        """
        groupDict = {}
        if type == 'url':
            for url in self.URLObjectList:
                for i in self.allUrlObjectList:
                    if url.getName() == i[0]:
                        urlName = url.getName()
                        urlID = i[1]
                        groupName = url.getGroupMembership()

                        for j in groupName:

                            if j not in groupDict:
                                groupDict[j] = []
                                groupDict[j].append({
                                    'type': 'Url',
                                    'id': urlID,
                                    'name': urlName
                                })

                            else:
                                groupDict[j].append({
                                    'type': 'Url',
                                    'id': urlID,
                                    'name': urlName
                                })
        elif type == 'network' or type == 'host' or type == 'fqdn':
            for network in self.networkObjectList:
                for i in self.allNetworkObjectList:
                    if i[0] == network.getName():

                        networkName = network.getName()
                        networkID = i[1]
                        groupName = network.getGroupMembership()

                        for j in groupName:

                            if j not in groupDict:
                                groupDict[j] = []
                                groupDict[j].append({
                                    'type': 'Network',
                                    'id': networkID,
                                    'name': networkName
                                })
                            else:
                                groupDict[j].append({
                                    'type': 'Network',
                                    'id': networkID,
                                    'name': networkName
                                })
            for fqdn in self.FQDNObjectList:
                for i in self.allFQDNObjects:
                    if i[0] == fqdn.getName():

                        fqdnName = fqdn.getName()
                        fqdnID = i[1]
                        groupName = fqdn.getGroupMembership()
                        for j in groupName:

                            if j not in groupDict:  # If group name is not in the dictionary then we add the group name and associate an empty list with the group and append the values in it
                                groupDict[j] = []
                                groupDict[j].append({
                                    'type': 'fqdn',
                                    'id': fqdnID,
                                    'name': fqdnName
                                })
                            else:
                                groupDict[j].append({
                                    'type': 'fqdn',
                                    'id': fqdnID,
                                    'name': fqdnName
                                })
            for host in self.hostObjectList:
                for i in self.allHostObjectList:
                    if i[0] == host.getName():

                        hostName = host.getName()
                        hostID = i[1]
                        groupName = host.getGroupMembership()
                        for j in groupName:

                            if j not in groupDict:  # If group name is not in the dictionary then we add the group name and associate an empty list with the group and append the values in it
                                groupDict[j] = []
                                groupDict[j].append({
                                    'type': 'Host',
                                    'id': hostID,
                                    'name': hostName
                                })
                            else:
                                groupDict[j].append({
                                    'type': 'Host',
                                    'id': hostID,
                                    'name': hostName
                                })


        return groupDict

    def deleteGroup(self, id, type):
        """
        Deletes the group with the mentioned id.
        :param id: The id of the group to be deleted.
        :param type: The type of the group to be deleted.
        :return: The status code of the request
        """
        groupLocation = self.networkGroupLocation if type == "network" else self.urlGroupLocation

        url = buildUrlForResourceWithId(self.fmcIP, self.domainLocation, self.domainId, groupLocation, id)

        self.logger.info("Deleting group. {Group Type: " + groupLocation  +"}")
        
        networks = requests.delete(
            url=url,
            headers=self.authHeader,
            verify=False
        )

        self.logger.info("Group deleted. {Id: " + id + ", Type: " + type + "}")
        return networks.status_code

    def appendToGroup(self, groupId, groupType, objectName, objectId, objectType):
            groupLocation = self.networkGroupLocation if groupType == "network" or "NetworkGroup" else self.urlGroupLocation

            url = buildUrlForResourceWithId(self.fmcIP, self.domainLocation, self.domainId, groupLocation, groupId)

            group = requests.get(
                url=url,
                headers=self.authHeader,
                verify=False
            )

            members = group.json()['objects']
            idgrp = group.json()['id']
            namegrp = group.json()['name']
            typegrp = group.json()['type']

            newObject = {}
            newObject["name"] = objectName
            newObject["id"] = objectId
            newObject["type"] = objectType

            members.append(newObject)

            group = requests.get(
                url=url,
                headers=self.authHeader,
                verify=False
            )

            payload = {"objects": members, "id": idgrp, "name": namegrp, "type": typegrp}
            response = requests.put(
                    url=url,
                    headers=self.authHeader,
                    data=payload.json(),
                    verify=False
            )

            return response.status_code

    def mergeDict(self, groupDict, temp_body):
        """
        A helper function, which merges dictionaries.
        :param groupDict: One of the dictionary to be merged.
        :param temp_body: The second dictionary to be merged.
        :return: The merged dictionary.
        """

        print("groupDict: ", groupDict)
        print("TTT body: ", temp_body)
        for group in groupDict:
            value = 0
            temp = group['name']
            for diction in temp_body[0]:
                if temp == diction['name']:
                    value += 1
            print("Value: ", value)
            if value == 0:
                temp_body[0].append(group)
                print("Done adding")



        print("Body: ", temp_body)

        return temp_body




    def createGroups(self, type):
        """
        Creates the object groups.
        :param type: The type of the group to be created.
        :return: None
        """
        groupDict = self.createGroupMembershipLists(type)
        temp = []

        for group in groupDict:
            if type == 'host' or type == 'fqdn':
                type = 'network'

            objGroup = ObjectGroup.GroupObject(self.domainId, group, type, groupDict[group], self.fmcIP)
            flag = True

            for i in self.allGroupsList:
                if i[0] == objGroup.getName():
                    print("This groupName named ", objGroup.getName(),
                          "already exists. Making a PUT request.")
                    temp_body = [i[4], i[6]]
                    print("Group test: ", groupDict[group])
                    print("Temp body: ", temp_body)
                    postBody = self.mergeDict(groupDict[group], temp_body)
                    print("Temp_body: ", postBody)

                    put_object = ObjectGroup.GroupObject(self.domainId, group, type, postBody, self.fmcIP)
                    put_object.modifyGroup(self.apiToken, i[1])
                    temp.append([objGroup.getName(), i[1], 'objects', type+'Group', postBody[0], 'literals', postBody[1]])
                    self.allGroupsList.remove(i)

                    pass

                if flag == True:
                    result = objGroup.createGroup(self.apiToken)
                    print("Making group: ", result)
                    if int(result) < 299:
                        temp.append([objGroup.getName(), objGroup.getUUID(), 'objects', objGroup.getGroupMembership()+'Group', groupDict[group], 'literals', []])
                        print("New group: ", temp)
                        print("Successfully created")
                        pass
        for j in temp:
            self.allGroupsList.append(j)
        print("All group objects: ", self.allGroupsList)

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
        """
        Adds the creation of Python objects and their addition in the respective object lists.
        :param domain: The domain UUID
        :param type: The type of the object to be added.
        :param name: The name of the object.
        :param value: Value of the object.
        :param description:
        :param group: The group in which the object is to be added.
        :return:
        """

        if type == 'host':
            self.__addHost(name, value, description, group)

        elif type == 'network':
            self.__addNetwork(name, value, description, group)

        elif type == 'url':
            self.__addURL(name, value, description, group)

        elif type == 'fqdn':
            self.__addFQDN(name, value, description, group)

        elif type == 'range':
            self.__addRange(name, value, description, group)

        elif type == 'TCP':
            self.__addTCP(name, value, description, group)

        elif type == 'UDP':
            self.__addUDP(name, value, description, group)

        else:
            return "Object type not configured"

    def getObjectList(self, objectType):
        """
        Retrieves the list of objects of the said type.
        :param objectType: The type of the objects whose list is to be returned.
        :return: The list containing the objects of the specified type.
        """

        match objectType:
            case "host":
                return self.hostObjectList
            case "network":
                return self.networkObjectList
            case "url":
                return self.URLObjectList
            case "fqdn":
                return self.FQDNObjectList
            case "range":
                return self.rangeObjectList
            case "TCP":
                return self.tcpObjectList
            case "UDP":
                return self.udpObjectList
            case "securityzone":
                return self.securityZoneObjectList
            case _:
                return None

    def applyObjectList(self, listType):
        """
        Creates the objects in FMC environment.
        :param listType: The type of the objects whose FMC objects are to be created.
        :return:
        """
        match listType:
            case "host":

                for host in self.hostObjectList:
                    flag_host = True
                    for i in self.allHostObjectList:

                        if i[0] == host.getName():
                            print("i host: ", i)
                            flag_host = False
                            if ((i[0] == host.getName()) and (i[2] == host.getValue())):
                                print(
                                    "Exactly same object so no need to delete. Condition 1.1 ", i[0])
                                flag_host = False
                            elif ((i[0] == host.getName()) and (i[2] != host.getValue())):
                                print(i[0], i[2],
                                      "Condition 1.2: There exists an object with the same name. Do you want to delete the existing object? Please answer Y/N: ")
                                ans = str(input())
                                if ans == 'Y':
                                    print("Condition 1.2.1")
                                    result = self.deleteHosts(i[1])
                                    if int(result) <= 299 and int(result) >= 200:
                                        self.allHostObjectList.remove(i)
                                    result = host.createHost(self.authHeader)
                                    if int(result) <= 299 and int(result) >= 200:
                                        self.allHostObjectList.append([host.getName(), host.getUUID(), host.getValue(), host.getType(), host.getDescription()])
                                else:
                                    print("Condition 1.2.2: Skipped this host.")

                    print(flag_host)
                    if flag_host == True:
                        print("Condition 2", host.getName())
                        result = host.createHost(self.authHeader)
                        if int(result) <= 299 and int(result) >= 200:
                            self.allHostObjectList.append(
                                [host.getName(), host.getUUID(), host.getValue(), host.getType(), host.getDescription()])
                        print(result)
            case "TCP":

                for tcp in self.tcpObjectList:
                    flag_tcp = True
                    for i in self.allPortObjectList:

                        if i[0] == tcp.getName():
                            print("i host: ", i)
                            flag_tcp = False
                            if ((i[0] == tcp.getName()) and (i[2] == tcp.getValue()) and i[3] == 'TCP'):
                                print("Exactly same object so no need to delete. Condition 1.1 ", i[0])
                                flag_tcp = False
                            elif ((i[0] == tcp.getName()) and (i[2] != tcp.getValue())):
                                print(i[0], i[2],
                                      "Condition 1.2: There exists an object with the same name. Do you want to delete the existing object? Please answer Y/N: ")
                                ans = str(input())
                                # if ans == 'Y':
                                #     print("Condition 1.2.1")
                                #     # result = self.deleteTCP(i[1])
                                #     # if int(result) <= 299 and int(result) >= 200:
                                #     #     self.allPortObjectList.remove(i)
                                #     result = tcp.createTCP(self.authHeader)
                                #     if int(result) <= 299 and int(result) >= 200:
                                #         self.allHostObjectList.append(
                                #             [tcp.getName(), tcp.getUUID(), tcp.getValue(), 'TCP', tcp.getType(),
                                #              tcp.getDescription()])
                                # else:
                                #     print("Condition 1.2.2: Skipped this host.")

                    print(flag_tcp)
                    if flag_tcp == True:
                        print("Condition 2", tcp.getName())
                        result = tcp.createTCP(self.authHeader)
                        if int(result) <= 299 and int(result) >= 200:
                            self.allPortObjectList.append(
                                [tcp.getName(), tcp.getID(), tcp.getValue(), 'TCP', tcp.getType(),
                                             tcp.getDescription()])
                        print(result)

                        print("After ports: ", self.allPortObjectList)
            case "UDP":

                for udp in self.udpObjectList:
                    flag_udp = True
                    for i in self.allPortObjectList:

                        if i[0] == udp.getName():
                            print("i host: ", i)
                            flag_udp = False
                            if ((i[0] == udp.getName()) and (i[2] == udp.getValue()) and i[3] == 'UDP'):
                                print("Exactly same object so no need to delete. Condition 1.1 ", i[0])
                                flag_udp = False
                            elif ((i[0] == udp.getName()) and (i[2] != udp.getValue())):
                                print(i[0], i[2],
                                      "Condition 1.2: There exists an object with the same name. Do you want to delete the existing object? Please answer Y/N: ")
                                ans = str(input())
                                # if ans == 'Y':
                                #     print("Condition 1.2.1")
                                #     # result = self.deleteTCP(i[1])
                                #     # if int(result) <= 299 and int(result) >= 200:
                                #     #     self.allPortObjectList.remove(i)
                                #     result = tcp.createTCP(self.authHeader)
                                #     if int(result) <= 299 and int(result) >= 200:
                                #         self.allHostObjectList.append(
                                #             [tcp.getName(), tcp.getUUID(), tcp.getValue(), 'TCP', tcp.getType(),
                                #              tcp.getDescription()])
                                # else:
                                #     print("Condition 1.2.2: Skipped this host.")

                    print(flag_udp)
                    if flag_udp == True:
                        print("Condition 2", udp.getName())
                        result = udp.createUDP(self.authHeader)
                        if int(result) <= 299 and int(result) >= 200:
                            self.allPortObjectList.append(
                                [udp.getName(), udp.getID(), udp.getValue(), 'UDP', udp.getType(),
                                 udp.getDescription()])
                        print(result)

                        print("After ports: ", self.allPortObjectList)

            case "network":
                for network in self.networkObjectList:
                    flag_network = True
                    for i in self.allNetworkObjectList:

                        if i[0] == network.getName():
                            flag_network = False
                            print("1: ", flag_network)
                            print(i[0], "Condition 1")
                            print("True for ", network.getGroupMembership(), "id: ", i)
                            if ((i[0] == network.getName()) and (i[2] == network.getValue())):
                                print(
                                    "Exactly same object so no need to delete. Condition 1.1 ", i[0])
                                flag_network = False
                            elif ((i[0] == network.getName()) and (i[2] != network.getValue())):
                                print(
                                    i[0], i[2], "Condition 1.2: There exists an object with the same name. Do you want to delete the existing object? Please answer Y/N: ")
                                ans = str(input())
                                if ans == 'Y':
                                    print("Condition 1.2.1")
                                    result = self.deleteNetwork(i[1])
                                    if int(result) <= 299 and int(result) >= 200:
                                        self.allNetworkObjectList.remove(i)

                                    authHeader = {"X-auth-access-token": self.apiToken}
                                    result = network.createNetwork(authHeader)
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
                        authHeader = {"X-auth-access-token": self.apiToken}
                        result = network.createNetwork(authHeader)
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
                                    result = url.createURL(self.authHeader)
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
                        result = url.createURL(self.authHeader)
                        if int(result) <= 299 and int(result) >= 200:
                            self.allUrlObjectList.append([url.getName(), url.getUUID(
                            ), url.getValue(), url.getType(), url.getDescription()])
                        print(result)
                        print("Name for: ", url.getName(),
                              " Id: ", url.getUUID())

            case "fqdn":

                for fqdn in self.FQDNObjectList:
                    flag_fqdn = True
                    for i in self.allFQDNObjects:

                        if i[0] == fqdn.getName():
                            flag_fqdn = False
                            if ((i[0] ==fqdn.getName()) and (i[2] == fqdn.getValue())):
                                print(
                                    "Exactly same object so no need to delete. Condition 1.1 ", i[0])
                                flag_fqdn = False
                            elif ((i[0] == fqdn.getName()) and (i[2] != fqdn.getValue())):
                                print(i[0], i[2],
                                      "Condition 1.2: There exists an object with the same name. Do you want to delete the existing object? Please answer Y/N: ")
                                ans = str(input())
                                if ans == 'Y':
                                    print("Condition 1.2.1")
                                    result = self.deleteFQDNs(i[1])
                                    if int(result) <= 299 and int(result) >= 200:
                                        self.allFQDNObjects.remove(i)
                                    result = fqdn.createFQDN(self.authHeader)
                                    if int(result) <= 299 and int(result) >= 200:
                                        self.allFQDNObjects.append([fqdn.getName(), fqdn.getID(
                                        ), fqdn.getValue(), fqdn.getType(), fqdn.getDescription()])
                                else:
                                    print("Condition 1.2.2: Skipped this fqdn.")

                    print(flag_fqdn)
                    if flag_fqdn == True:
                        print("Condition 2", fqdn.getName())
                        result = fqdn.createFQDN(self.authHeader)
                        if int(result) <= 299 and int(result) >= 200:
                            self.allFQDNObjects.append([fqdn.getName(), fqdn.getID(), fqdn.getValue(), fqdn.getType(), fqdn.getDescription()])
                        print(result)

            case "range":

                for range in self.rangeObjectList:
                    flag_range = True
                    for i in self.allRangeObjects:

                        if i[0] == range.getName():
                            flag_range = False
                            if ((i[0] == range.getName()) and (i[2] == range.getValue())):
                                print(
                                    "Exactly same object so no need to delete. Condition 1.1 ", i[0])
                                flag_range = False
                            elif ((i[0] == range.getName()) and (i[2] != range.getValue())):
                                print(i[0], i[2],
                                      "Condition 1.2: There exists an object with the same name. Do you want to delete the existing object? Please answer Y/N: ")
                                ans = str(input())
                                if ans == 'Y':
                                    print("Condition 1.2.1")
                                    result = self.deleteRange(i[1])
                                    if int(result) <= 299 and int(result) >= 200:
                                        self.allRangeObjects.remove(i)
                                    result = range.createRange(self.authHeader)
                                    if int(result) <= 299 and int(result) >= 200:
                                        self.allRangeObjects.append([range.getName(), range.getID(
                                        ), range.getValue(), range.getType(), range.getDescription()])
                                else:
                                    print("Condition 1.2.2: Skipped this range.")

                    print(flag_range)
                    if flag_range == True:
                        print("Condition 2", range.getName())
                        result = range.createRange(self.authHeader)
                        if int(result) <= 299 and int(result) >= 200:
                            self.allRangeObjects.append(
                                [range.getName(), range.getID(), range.getValue(), range.getType(), range.getDescription()])
                        print(result)

            case _:
                return None

    def __getSecurityZones(self):
        """
        Retrieves the security zones from FMC environment.
        :return: The list containing the details of all the security zones.
        """

        url = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, self.securityZoneLocation)

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

    def __getAllPortObjects(self):
        """
        Retrieves the ports from FMC environment.
        :return: The list containing the details of all the ports.
        """

        portCount = 0
        url = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, self.portLocation)
        queryParameters = {}
        queryParameters['limit'] = 2000
        queryParameters['offset'] = 0

        ports = requests.get(
            url=url,
            headers=self.authHeader,
            params=queryParameters,
            verify=False
        )

        ports = ports.json()['items']
        print("Alllll ports: ", ports)
        returnList = []

        for cat in ports:
            del cat['links']

            newUrl = buildUrlForResourceWithId(self.fmcIP, self.domainLocation, self.domainId, self.portLocation, cat['id'])

            port = requests.get(
                url=newUrl,
                headers=self.authHeader,
                verify=False
            )
            # print("Before: ", port.content)

            port = port.json()
            # print("After: ", port)
            # print("Main port: ", port)
            # print(port['name'], port['port'])


            # if port and port["name"]:
            #     self.logger.info("Network retrieved. {Name: " + port['name'] + ", Value: " + port['port'] + "}")
            if 'port' in port.keys():
                returnList.append([port['name'], port['id'],
                                   port['port'], port['protocol'], port['type'], port['description']])
            else:
                print("The port ", port['name'], " does not have a port value associated with it.")


        print("All ports: ", returnList)

        return returnList

        # ports = ports.json()['items']
        # returnList = []
        # print("All ports json: ", ports)
        #
        # for port in ports:
        #     del port['links']
        #     # portCount + 1
        #     returnList.append(Port.PortObject(port['name'], port['id']))
        #
        # # self.logger.info("Port objects added to list. {Ports:" + str(portCount) + "}")
        # print("All ports: ", returnList)
        #
        # return returnList

    def __getFilePolicies(self):
        """
        Retrieves the file policies from FMC environment.
        :return: The list containing the details of all the file policies.
        """

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
        """
        Retrieves the URL Categories from FMC environment.
        :return: The list containing the details of all the URL Categories.
        """

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
        """
        Retrieves the Applications from FMC environment.
        :return: The list containing the details of all Applications.
        """

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
        """
        Retrieves the Networks from FMC environment.
        :return: The list containing the details of all the Networks.
        """

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

            newUrl = buildUrlForResourceWithId(self.fmcIP, self.domainLocation, self.domainId, self.networkLocation,
                                               cat['id'])

            network = requests.get(
                url=newUrl,
                headers=self.authHeader,
                verify=False
            )

            network = network.json()

            # if network and network["name"]:
            #     self.logger.info("Network retrieved. {Name: " + network['name'] + ", Value: " + network['value'] + "}")

            returnList.append([network['name'], network['id'],
                               network['value'], network['type'], network['description']])

        return returnList

    def __getAllUrls(self):
        """
        Retrieves the URLs from FMC environment.
        :return: The list containing the details of all the URLs.
        """
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

            newURL = buildUrlForResourceWithId(self.fmcIP, self.domainLocation, self.domainId, self.urlLocation,
                                               cat['id'])

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
        """
        Retrieves the Hosts from FMC environment.
        :return: The list containing the details of all the Hosts.
        """
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

            newURL = buildUrlForResourceWithId(self.fmcIP, self.domainLocation, self.domainId, self.hostLocation,
                                               cat['id'])

            host = requests.get(
                url=newURL,
                headers=self.authHeader,
                verify=False
            )

            host = host.json()
            returnList.append(
                [host['name'], host['id'], host['value'], host['type'], host['description']])

        return returnList

    def __getAllFQDNs(self):
        """
        Retrieves the FQDNs from FMC environment.
        :return: The list containing the details of all the FQDNs.
        """
        url = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, self.fqdnLocation)

        fqdn = requests.get(
            url=url,
            headers=self.authHeader,
            verify=False
        )

        returnList = []
        print("FQDN all response: ", fqdn.json())
        if 'items' in fqdn.json().keys():
            fqdns = fqdn.json()['items']


            for cat in fqdns:
                del cat['links']

                newURL = buildUrlForResourceWithId(self.fmcIP, self.domainLocation, self.domainId, self.fqdnLocation,
                                                   cat['id'])

                fqdn = requests.get(
                    url=newURL,
                    headers=self.authHeader,
                    verify=False
                )

                fqdn = fqdn.json()
                returnList.append([fqdn['name'], fqdn['id'], fqdn['value'], fqdn['type'], fqdn['description']])

        return returnList

    def __getAllRanges(self):
        url = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, self.rangeLocation)

        range = requests.get(
            url=url,
            headers=self.authHeader,
            verify=False
        )

        returnList = []
        print("Range all response: ", range.json())
        if 'items' in range.json().keys():
            ranges = range.json()['items']

            for cat in ranges:
                del cat['links']

                newURL = buildUrlForResourceWithId(self.fmcIP, self.domainLocation, self.domainId, self.rangeLocation,
                                                   cat['id'])

                range = requests.get(
                    url=newURL,
                    headers=self.authHeader,
                    verify=False
                )

                range = range.json()
                returnList.append([range['name'], range['id'], range['value'], range['type'], range['description']])
        print("Ranges list: ", returnList)

        return returnList

    def __getNetworkGroups(self):

        url = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, self.networkGroupLocation)

        nwGroups = requests.get(
            url=url,
            headers=self.authHeader,
            verify=False
        )

        nwGroups = nwGroups.json()
        print("NW groups: ", nwGroups)

    def __getAllGroups(self):
        """
        Retrieves the list of all the object groups from FMC environment.
        :return: The list containing details of all the groups.
        """
        url = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, self.networkGroupLocation)

        nwGroup = requests.get(
            url=url,
            headers=self.authHeader,
            verify=False
        )

        nwGroup = nwGroup.json()['items']
        print("All nw groups1: ", nwGroup)
        returnList = []

        for cat in nwGroup:
            del cat['links']

            newUrl = buildUrlForResourceWithId(self.fmcIP, self.domainLocation, self.domainId,
                                               self.networkGroupLocation, cat['id'])

            nw = requests.get(
                url=newUrl,
                headers=self.authHeader,
                verify=False
            )
            print("One nw: ", nw.json())
            if 'objects' in nw.json().keys() and 'literals' in nw.json().keys():
                returnList.append([cat['name'], cat['id'], 'objects', cat['type'], nw.json()['objects'], 'literals', nw.json()['literals']])
            if 'objects' in nw.json().keys() and 'literals' not in nw.json().keys():
                returnList.append([cat['name'], cat['id'], 'objects', cat['type'], nw.json()['objects'], 'literals', []])
            if 'objects' not in nw.json().keys() and 'literals' in nw.json().keys():
                returnList.append([cat['name'], cat['id'], 'objects', cat['type'], [], 'literals', nw.json()['literals']])
            if 'objects' not in nw.json().keys() and 'literals' not in nw.json().keys():
                returnList.append([cat['name'], cat['id'], 'objects', cat['type'], [], 'literals', []])

        url2 = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, self.urlGroupLocation)

        nwGroup = requests.get(
            url=url2,
            headers=self.authHeader,
            verify=False
        )

        urlGroup = nwGroup.json()['items']
        # returnList = []

        for cat in urlGroup:
            del cat['links']

            newUrl = buildUrlForResourceWithId(self.fmcIP, self.domainLocation, self.domainId,
                                               self.urlGroupLocation, cat['id'])

            nw = requests.get(
                url=newUrl,
                headers=self.authHeader,
                verify=False
            )
            if 'objects' in nw.json().keys() and 'literals' in nw.json().keys():
                returnList.append([cat['name'], cat['id'], 'objects', cat['type'], nw.json()['objects'], 'literals',
                                   nw.json()['literals']])
            if 'objects' in nw.json().keys() and 'literals' not in nw.json().keys():
                returnList.append(
                    [cat['name'], cat['id'], 'objects', cat['type'], nw.json()['objects'], 'literals', []])
            if 'objects' not in nw.json().keys() and 'literals' in nw.json().keys():
                returnList.append(
                    [cat['name'], cat['id'], 'objects', cat['type'], [], 'literals', nw.json()['literals']])
            if 'objects' not in nw.json().keys() and 'literals' not in nw.json().keys():
                returnList.append([cat['name'], cat['id'], 'objects', cat['type'], [], 'literals', []])
        print("Create group returnList: ", returnList)

        return returnList

    def deleteNetwork(self, id):
        """
        Deletes the Network object from FMC environment.
        :param id: The id of the network object to be deleted.
        :return: The status code of the deletion request.
        """
        url = buildUrlForResourceWithId(self.fmcIP, self.domainLocation, self.domainId, self.networkLocation, id)
        networks = requests.delete(
            url=url,
            headers=self.authHeader,
            verify=False
        )

        return networks.status_code

    def deleteUrls(self, id):
        """
        Deletes the URL object from FMC environment.
        :param id: The id of the URL object to be deleted.
        :return: The status code of the deletion request.
        """
        url = buildUrlForResourceWithId(self.fmcIP, self.domainLocation, self.domainId, self.urlLocation, id)
        networks = requests.delete(
            url=url,
            headers=self.authHeader,
            verify=False
        )

        return networks.status_code

    def deleteHosts(self, id):
        """
        Deletes the Host object from FMC environment.
        :param id: The id of the Host object to be deleted.
        :return: The status code of the deletion request.
        """
        url = buildUrlForResourceWithId(self.fmcIP, self.domainLocation, self.domainId, self.hostLocation, id)
        networks = requests.delete(
            url=url,
            headers=self.authHeader,
            verify=False
        )

        return networks.status_code

    def deleteFQDNs(self, id):
        """
        Deletes the FQDN object from FMC environment.
        :param id: The id of the FQDN object to be deleted.
        :return: The status code of the deletion request.
        """
        url = buildUrlForResourceWithId(self.fmcIP, self.domainLocation, self.domainId, self.fqdnLocation, id)
        networks = requests.delete(
            url=url,
            headers=self.authHeader,
            verify=False
        )

        return networks.status_code

    def deleteRange(self, id):
        url = buildUrlForResourceWithId(self.fmcIP, self.domainLocation, self.domainId, self.rangeLocation, id)
        range = requests.delete(
            url=url,
            headers=self.authHeader,
            verify=False
        )
        print(range.json())

        return range.status_code
    def mergeAllNetworkTypes(self):
        """
        Makes a collective list of all the Network types.
        :return: The list containing all the hosts, networks, and FQDNs.
        """
        networks = self.allNetworkObjectList
        hosts = self.allHostObjectList

        for i in hosts:
            networks.append(i)

        for i in self.allFQDNObjects:
            networks.append(i)
        print("All groups: ", self.allGroupsList)
        for i in self.allGroupsList:
            print("type", i[3])
            if i[3] == 'NetworkGroup':
                networks.append([i[0], i[1], i[4], i[3], ''])

        return networks
    def mergeURLwithURLGroups(self):
        urls = self.allUrlObjectList
        # print("Before merging: ", urls)

        for i in self.allGroupsList:
            print("type url", i[3])
            if i[3] == 'UrlGroup':
                urls.append([i[0], i[1], i[4], i[3], ''])
        return urls
    def createAccessRule(self, csvRow, ruleCategory):
        """
        Creates policy rules line by line from the csv file.
        :param csvRow: The line in csv file containing all the details of the rule.
        :return:
        """
        allNetworks = self.mergeAllNetworkTypes()
        allUrls = self.mergeURLwithURLGroups()
        print("Merged urlS: ", allUrls)

        policyObject = AccessPolicy.AccessPolicyObject.FMCAccessPolicyObject(self, '005056B6-DCA2-0ed3-0000-017179871248', self.securityZoneObjectList, allNetworks,
                                                       self.allPortObjectList, self.filePolicyObjectList, self.urlCategoryObjectList, allUrls, self.allGroupsList, self.applicationObjectList, ruleCategory)
        
        response = policyObject.createPolicy(self.apiToken, csvRow, ruleCategory)

        return response

    def createNATRules(self, csvRow, ruleCategory):
        """
        Creates Auto NAT rules line by line from the csv file containing all the rules.
        :param csvRow: The csv row, that is the line containing all the details of the NAT rule to be added.
        :return: The response for the rule creation request.
        """

        allNetworks = self.mergeAllNetworkTypes()

        policyObject = AccessPolicy.AccessPolicyObject.FMCAccessPolicyObject(self,
                                                                             '',
                                                                             self.securityZoneObjectList,
                                                                             allNetworks,
                                                                             self.allPortObjectList,
                                                                             self.filePolicyObjectList,
                                                                             self.urlCategoryObjectList,
                                                                             self.allUrlObjectList, self.allGroupsList,
                                                                             self.applicationObjectList, ruleCategory)

        response = policyObject.createNATRules(self.apiToken, csvRow)

        return response

    def createManualNATrule(self, csvRow, ruleCategory):
        """
        Creates Manual NAT rules line by line from the csv file containing all the rules.
        :param csvRow: The csv row, that is the line containing all the details of the NAT rule to be added.
        :return: The response of the rule creation request.
        """
        allNetworks = self.mergeAllNetworkTypes()

        policyObject = AccessPolicy.AccessPolicyObject.FMCAccessPolicyObject(self,
                                                                             '',
                                                                             self.securityZoneObjectList,
                                                                             allNetworks,
                                                                             self.allPortObjectList,
                                                                             self.filePolicyObjectList,
                                                                             self.urlCategoryObjectList,
                                                                             self.allUrlObjectList, self.allGroupsList,
                                                                             self.applicationObjectList, ruleCategory)

        response = policyObject.createManualNATrule(self.apiToken, csvRow)

        return response




