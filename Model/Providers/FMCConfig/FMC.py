import requests
import time
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

        self.authHeader = {"X-auth-access-token": self.apiToken, "Retry-After": "3600"}

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


        self.allPortObjectList = self.__getAllPortObjects() #required
        self.allRangeObjects = self.__getAllRanges() #required
        self.securityZoneObjectList = self.__getSecurityZones() #required
        self.filePolicyObjectList = self.__getFilePolicies()
        self.urlCategoryObjectList = self.__getURLCategories() #required
        self.applicationObjectList = self.__getApplications() #required
        # self.allNetworkGroupObjectList = self.__getAllNetworkGroups()
        self.allNetworkObjectList = self.__getAllNetworks() #required
        self.allGroupsList = self.__getAllGroups() #required
        # self.allUrlGroupList = self.__getAllUrlGroups()
        self.allUrlObjectList = self.__getAllUrls() #required
        self.allHostObjectList = self.__getAllHosts() #required
        self.allFQDNObjects = self.__getAllFQDNs() #required
        # self.allNetworkGroups = self.__getNetworkGroups()

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
        
        response = requests.post(
                url = 'https://' + self.fmcIP + '/api/fmc_platform/v1/auth/generatetoken',
                auth=HTTPBasicAuth(username, password),
                data={},
                verify=False
            )


        #TODO Is there multiple domains on FMC? If so how are we making sure we get the correct one. 
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
        

    def __addHost(self, name: str, value: str, description='', group='', groupDescription=''):
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
        #TODO Why is this commented?
        #if group:
        #    self.CheckAndAddGroup(group)
        
        hostObj = Host.HostObject.FMCHost(self, name, value, description, group, groupDescription)
        print("Host description: ", hostObj.getGroupDescription(), hostObj.getGroupMembership())
        # self.logger.info("Host added. {Name: " + name + ", Value: " + group + "}")
        return self.hostObjectList.append(hostObj)

    def __addNetwork(self, name: str, value: str, description='', group='', groupDescription=''):
        """
        Creates a Network object with the FMC constructor and adds it to the Network Object List.

        :param name: Name of the network to be added.
        :param value: The value of the network.
        :param description: Description of the network. It is optional and defaults to ''.
        :param group: The name of the Network object group which the network object should be added to.
        :return:  None: The Network object is appended to the Network Object List
        """
        networkObj = Network.NetworkObject.FMCNetwork(self, name, value, description, group, groupDescription)
        print("Network description: ", networkObj.getGroupDescription(), networkObj.getGroupMembership())
        self.logger.info("Network added. {Name: " + name + ", Value: " + value + "}")
        return self.networkObjectList.append(networkObj)

    def __addURL(self, name, url, description='', group='', groupDescription=''):
        """
            Creates a Network object with the FMC constructor and adds it to the URL Object List.

            :param name: Name of the URL to be added.
            :param url: The value of the URL.
            :param description: Description of the network. It is optional and defaults to ''.
            :param group: The name of the URL object group in which the URL should be added.
            :return:  None: The URL object is appended to the URL Object list.
        """
        urlObj = URL.URLObject.FMCUrlObject(self, name, url, description, group, groupDescription)
        print("URL description: ", urlObj.getGroupDescription(), urlObj.getGroupMembership())
        self.logger.info("URL added. {Name: " + name + ", Value: " + url + "}")
        return self.URLObjectList.append(urlObj)

    def __addFQDN(self, name, value, description='', group='', groupDescription=''):
        """
            Creates a FQDN object with the FMC constructor and adds it to the FQDN Object list.

            :param name: Name of the FQDN to be added.
            :param value: The value of FQDN.
            :param description: Description of the FQDN being added. It is optional and defaults to ''.
            :param group: The name of the FQDN object group in which the FQDN should be added.
            :return:  None: The FQDN object is appended to the FQDN Object list.
        """

        fqdnObj = FQDN.FQDNObject.FMCFQDN(self, name, value, description, group, groupDescription)
        print("FQDN description: ", fqdnObj.getGroupDescription(), fqdnObj.getGroupMembership())
        self.logger.info("FQDN added. {Name: " + name + ", Value: " + value + "}")
        return self.FQDNObjectList.append(fqdnObj)

    def __addRange(self, name, value, description='', group='', groupDescription=''):
        #TODO Missing Docstring
        rangeObj = Range.RangeObject.FMCRange(self, name, value, description, group, groupDescription)
        print("Host description: ", rangeObj.getGroupDescription(), rangeObj.getGroupMembership())
        self.logger.info("Range added. {Name: " + name + ", Value: " + value + "}")
        return self.rangeObjectList.append(rangeObj)

    def __addTCP(self, name, value, description='', group='', groupDescription=''):
        #TODO Missing Docstring

        tcpObj = TCP.TCPObject.FMCTCP(self, name, value, description)
        self.logger.info("TCP added. {Name: " + name + ", Value: " + value + "}")
        return self.tcpObjectList.append(tcpObj)

    def __addUDP(self, name, value, description='', group='', groupDescription=''):
        #TODO Missing Docstring

        udpObj = UDP.UDPObject.FMCUDP(self, name, value, description, group)
        self.logger.info("UDP added. {Name: " + name + ", Value: " + value + "}")
        return self.udpObjectList.append(udpObj)


    def createGroupMembershipLists(self, type):
        """
        Makes the list of groups and the objects which are to be added in the respective groups.

        :param type: The type of the groups being created. Type 'url' will result in UrlGroups, and hosts,
                     FQDNs, and Networks will result in NetworkGroups

        :return: The dictionary containing all the group names and their constituent objects. (Where do objects come from? Elaborate.)
        """
        groupDict = {}
        groupDesc = {}
        if type == 'url':
            for url in self.URLObjectList:
                for i in self.allUrlObjectList:
                    if url.getName() == i[0]:
                        urlName = url.getName()
                        urlID = i[1]

                        groupName = url.getGroupMembership()
                        urlGroupDescription = url.getGroupDescription()

                        for j in groupName:

                            if j not in groupDict:
                                groupDict[j] = []
                                groupDesc[j] = ''
                                groupDesc[j] = urlGroupDescription
                                # groupDict['description'] = urlGroupDescription
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
        elif type == 'network' or type == 'host' or type == 'fqdn' or type == 'range':
            for network in self.networkObjectList:
                for i in self.allNetworkObjectList:
                    if i[0] == network.getName():

                        networkName = network.getName()
                        networkID = i[1]
                        groupName = network.getGroupMembership()
                        networkGroupDescription = network.getGroupDescription()

                        for j in groupName:

                            if j not in groupDict:
                                groupDict[j] = []
                                groupDesc[j] = networkGroupDescription
                                # groupDict['description'] = networkGroupDescription
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
                        fqdnGroupDescription = fqdn.getGroupDescription()
                        for j in groupName:

                            if j not in groupDict:  # If group name is not in the dictionary then we add the group name and associate an empty list with the group and append the values in it
                                groupDict[j] = []
                                groupDesc[j] = fqdnGroupDescription
                                # groupDict['description'] = fqdnGroupDescription
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
                        hostGroupDescription = host.getGroupDescription()
                        for j in groupName:

                            if j not in groupDict:  # If group name is not in the dictionary then we add the group name and associate an empty list with the group and append the values in it
                                groupDict[j] = []
                                groupDesc[j] = hostGroupDescription
                                # groupDict['description'] = hostGroupDescription
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

            for range in self.rangeObjectList:
                for i in self.allRangeObjects:
                    if i[0] == range.getName():

                        rangeName = range.getName()
                        rangeID = i[1]
                        groupName = range.getGroupMembership()
                        rangeGroupDescription = range.getGroupDescription()
                        for j in groupName:

                            if j not in groupDict:  # If group name is not in the dictionary then we add the group name and associate an empty list with the group and append the values in it
                                groupDict[j] = []
                                groupDesc[j] = rangeGroupDescription
                                # groupDict['description'] = rangeGroupDescription
                                groupDict[j].append({
                                    'type': 'Host',
                                    'id': rangeID,
                                    'name': rangeName
                                })
                            else:
                                groupDict[j].append({
                                    'type': 'Host',
                                    'id': rangeID,
                                    'name': rangeName
                                })

        # print("GroupDict: ", groupDict)
        # print("GroupDesc: ", groupDesc)

        returnList = [groupDict, groupDesc]


        return returnList

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
        #TODO Missing Docstring.

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

        for group in groupDict:
            value = 0
            temp = group['name']
            for diction in temp_body[0]:
                if temp == diction['name']:
                    value += 1

            if value == 0:
                temp_body[0].append(group)
                # print("Done adding")



        return temp_body




    def createGroups(self, type):
        """
        Creates the object groups.
        :param type: The type of the group to be created.
        :return: None
        """
        groupDict = self.createGroupMembershipLists(type)
        temp = []

        for group in groupDict[0]:
            if type == 'host' or type == 'fqdn':
                type = 'network'
            # print("group details: ", groupDict[0], "more: ", groupDict[1])
            # print("Values1: ", groupDict[0].get(group))
            # print("Values2: ", groupDict[1].get(group))

            objGroup = ObjectGroup.GroupObject(self.domainId, group, type, groupDict[0].get(group), self.fmcIP, groupDict[1].get(group))
            flag = True

            for i in self.allGroupsList:
                if i[0] == objGroup.getName():
                    print("This groupName named ", objGroup.getName(),
                          "already exists. Making a PUT request.")
                    temp_body = [i[4], i[6]]
                   
                    postBody = self.mergeDict(groupDict[0][group], temp_body)

                    put_object = ObjectGroup.GroupObject(self.domainId, group, type, postBody, self.fmcIP, '')
                    put_object.modifyGroup(self.authHeader, i[1])
                    temp.append([objGroup.getName(), i[1], 'objects', type+'Group', postBody[0], 'literals', postBody[1]])
                    self.allGroupsList.remove(i)

                    pass

                if flag == True:
                    result = objGroup.createGroup(self.authHeader)
                    # print("Making group: ", result)
                    if int(result) < 299:
                        temp.append([objGroup.getName(), objGroup.getUUID(), 'objects', objGroup.getGroupMembership()+'Group', groupDict[0][group], 'literals', []])
                        # print("New group: ", temp)
                        # print("Successfully created")
                        pass
        for j in temp:
            self.allGroupsList.append(j)
        # print("All group objects: ", self.allGroupsList)

    def compareContainingObjects(self, groupDict, objectDict):
        #TODO Missing Docstring

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

    def addObject(self, domain, type, name, value, description='', group='', groupDescription=''):
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
            self.__addHost(name, value, description, group, groupDescription)

        elif type == 'network':
            self.__addNetwork(name, value, description, group, groupDescription)

        elif type == 'url':
            self.__addURL(name, value, description, group, groupDescription)

        elif type == 'fqdn':
            self.__addFQDN(name, value, description, group, groupDescription)

        elif type == 'range':
            self.__addRange(name, value, description, group, groupDescription)

        elif type == 'TCP':
            self.__addTCP(name, value, description, group, groupDescription)

        elif type == 'UDP':
            self.__addUDP(name, value, description, group, groupDescription)

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
                            # print("i host: ", i)
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
                                    # print("Condition 1.2.1")
                                    result = self.deleteHosts(i[1])
                                    if int(result) <= 299 and int(result) >= 200:
                                        self.allHostObjectList.remove(i)
                                    result = host.createHost(self.authHeader)
                                    if int(result) <= 299 and int(result) >= 200:
                                        self.allHostObjectList.append([host.getName(), host.getUUID(), host.getValue(), host.getType(), host.getDescription()])
                                else:
                                    print("Condition 1.2.2: Skipped this host.")

                    # print(flag_host)
                    if flag_host == True:
                        # print("Condition 2", host.getName())
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
                            # print("i host: ", i)
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

                    # print(flag_tcp)
                    if flag_tcp == True:
                        # print("Condition 2", tcp.getName())
                        result = tcp.createTCP(self.authHeader)
                        if int(result) <= 299 and int(result) >= 200:
                            self.allPortObjectList.append(
                                [tcp.getName(), tcp.getID(), tcp.getValue(), 'TCP', tcp.getType(),
                                             tcp.getDescription()])
                        print(result)

                        # print("After ports: ", self.allPortObjectList)
            case "UDP":

                for udp in self.udpObjectList:
                    flag_udp = True
                    for i in self.allPortObjectList:

                        if i[0] == udp.getName():
                            # print("i host: ", i)
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

                    # print(flag_udp)
                    if flag_udp == True:
                        # print("Condition 2", udp.getName())
                        result = udp.createUDP(self.authHeader)
                        if int(result) <= 299 and int(result) >= 200:
                            self.allPortObjectList.append(
                                [udp.getName(), udp.getID(), udp.getValue(), 'UDP', udp.getType(),
                                 udp.getDescription()])
                        print(result)

                        # print("After ports: ", self.allPortObjectList)

            case "network":
                for network in self.networkObjectList:
                    flag_network = True
                    for i in self.allNetworkObjectList:

                        if i[0] == network.getName():
                            flag_network = False
                            # print("1: ", flag_network)
                            # print(i[0], "Condition 1")
                            # print("True for ", network.getGroupMembership(), "id: ", i)
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

                                    # authHeader = {"X-auth-access-token": self.apiToken}
                                    result = network.createNetwork(self.authHeader)
                                    if int(result) <= 299 and int(result) >= 200:
                                        self.allNetworkObjectList.append([network.getName(), network.getUUID(
                                        ), network.getValue(), network.getType(), network.getDescription()])

                                    print("result crete network: ", result)
                                    # print("Name for: ", network.getName(),
                                    #       " Id: ", network.getUUID())
                                else:
                                    print(
                                        "Condition 1.2.2: Skipped this network.")

                    # print(flag_network)
                    if flag_network == True:
                        # print("Condition 2", network.getName())
                        # authHeader = {"X-auth-access-token": self.apiToken}
                        result = network.createNetwork(self.authHeader)
                        if int(result) <= 299 and int(result) >= 200:
                            self.allNetworkObjectList.append([network.getName(), network.getUUID(
                            ), network.getValue(), network.getType(), network.getDescription()])
                        print(result)
                        # print("Name for: ", network.getName(),
                        #       " Id: ", network.getUUID())

            case "url":
                for url in self.URLObjectList:
                    flag_url = True
                    for i in self.allUrlObjectList:

                        if i[0] == url.getName():
                            flag_url = False
                            # print("1: ", flag_url)
                            # print(i[0], "Condition 1")
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
                                    # print("Condition 1.2.1")
                                    result = self.deleteUrls(i[1])
                                    if int(result) <= 299 and int(result) >= 200:
                                        self.allUrlObjectList.remove(i)
                                    result = url.createURL(self.authHeader)
                                    if int(result) <= 299 and int(result) >= 200:
                                        self.allUrlObjectList.append([url.getName(), url.getUUID(
                                        ), url.getValue(), url.getType(), url.getDescription()])
                                    print("result crete url: ", result)
                                    # print("Name for: ", url.getName(),
                                    #       " Id: ", url.getUUID())
                                else:
                                    print("Condition 1.2.2: Skipped this url.")

                    # print(flag_url)
                    if flag_url == True:
                        # print("Condition 2", url.getName())
                        result = url.createURL(self.authHeader)
                        if int(result) <= 299 and int(result) >= 200:
                            self.allUrlObjectList.append([url.getName(), url.getUUID(
                            ), url.getValue(), url.getType(), url.getDescription()])
                        print(result)
                        # print("Name for: ", url.getName(),
                        #       " Id: ", url.getUUID())

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
                                    # print("Condition 1.2.1")
                                    result = self.deleteFQDNs(i[1])
                                    if int(result) <= 299 and int(result) >= 200:
                                        self.allFQDNObjects.remove(i)
                                    result = fqdn.createFQDN(self.authHeader)
                                    if int(result) <= 299 and int(result) >= 200:
                                        self.allFQDNObjects.append([fqdn.getName(), fqdn.getID(
                                        ), fqdn.getValue(), fqdn.getType(), fqdn.getDescription()])
                                else:
                                    print("Condition 1.2.2: Skipped this fqdn.")

                    # print(flag_fqdn)
                    if flag_fqdn == True:
                        # print("Condition 2", fqdn.getName())
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
                                    # print("Condition 1.2.1")
                                    result = self.deleteRange(i[1])
                                    if int(result) <= 299 and int(result) >= 200:
                                        self.allRangeObjects.remove(i)
                                    result = range.createRange(self.authHeader)
                                    if int(result) <= 299 and int(result) >= 200:
                                        self.allRangeObjects.append([range.getName(), range.getID(
                                        ), range.getValue(), range.getType(), range.getDescription()])
                                else:
                                    print("Condition 1.2.2: Skipped this range.")

                    # print(flag_range)
                    if flag_range == True:
                        # print("Condition 2", range.getName())
                        result = range.createRange(self.authHeader)
                        if int(result) <= 299 and int(result) >= 200:
                            self.allRangeObjects.append(
                                [range.getName(), range.getID(), range.getValue(), range.getType(), range.getDescription()])
                        print(result)

            case _:
                return None



    # def applyObjectList(self, listType):
    #     """
    #     Creates the objects in FMC environment.
    #     :param listType: The type of the objects whose FMC objects are to be created.
    #     :return:
    #     """
    #     match listType:
    #         case "host":
    #             for host in self.hostObjectList:
    #                 result = host.createHost(self.authHeader)
    #
    #                 if int(result) > 399:
    #                     return result
    #         case "network":
    #             for network in self.networkObjectList:
    #                 result = network.createNetwork(self.authHeader)
    #
    #                 if int(result) > 399:
    #                     return result
    #         case "fqdn":
    #             for fqdn in self.FQDNObjectList:
    #                 result = fqdn.createFQDN(self.authHeader)
    #
    #                 if int(result) > 399:
    #                     return result
    #         case "url":
    #             for url in self.URLObjectList:
    #                 result = url.createURL(self.authHeader)
    #
    #                 if int(result) > 399:
    #                     return result
    #         case "tcp":
    #             for tcp in self.tcpObjectList:
    #                 result = tcp.createTCP(self.authHeader)
    #
    #                 if int(result) > 399:
    #                     return result
    #         case "udp":
    #             for udp in self.udpObjectList:
    #                 result = udp.createUDP(self.authHeader)
    #
    #                 if int(result) > 399:
    #                     return result
    #         case _:
    #             return None
                # flag_host = True
                    # for i in self.allHostObjectList:
                    #
                    #     if i[0] == host.getName():
                    #         print("i host: ", i)
                    #         flag_host = False
                    #         if ((i[0] == host.getName()) and (i[2] == host.getValue())):
                    #             print(
                    #                 "Exactly same object so no need to delete. Condition 1.1 ", i[0])
                    #             flag_host = False
                    #         elif ((i[0] == host.getName()) and (i[2] != host.getValue())):
                    #             print(i[0], i[2],
                    #                   "Condition 1.2: There exists an object with the same name. Do you want to delete the existing object? Please answer Y/N: ")
                    #             ans = str(input())
                    #             if ans == 'Y':
                    #                 print("Condition 1.2.1")
                    #                 result = self.deleteHosts(i[1])
                    #                 if int(result) <= 299 and int(result) >= 200:
                    #                     self.allHostObjectList.remove(i)
                    #                 result = host.createHost(self.authHeader)
                    #                 if int(result) <= 299 and int(result) >= 200:
                    #                     self.allHostObjectList.append([host.getName(), host.getUUID(), host.getValue(), host.getType(), host.getDescription()])
                    #             else:
                    #                 print("Condition 1.2.2: Skipped this host.")
                    #
                    # print(flag_host)
                    # if flag_host == True:
                    #     print("Condition 2", host.getName())
                    #     result = host.createHost(self.authHeader)
                    #     if int(result) <= 299 and int(result) >= 200:
                    #         self.allHostObjectList.append(
                    #             [host.getName(), host.getUUID(), host.getValue(), host.getType(), host.getDescription()])
                    #     print(result)
            # case "TCP":
            #
            #     for tcp in self.tcpObjectList:
            #         flag_tcp = True
            #         for i in self.allPortObjectList:
            #
            #             if i[0] == tcp.getName():
            #                 print("i host: ", i)
            #                 flag_tcp = False
            #                 if ((i[0] == tcp.getName()) and (i[2] == tcp.getValue()) and i[3] == 'TCP'):
            #                     print("Exactly same object so no need to delete. Condition 1.1 ", i[0])
            #                     flag_tcp = False
            #                 elif ((i[0] == tcp.getName()) and (i[2] != tcp.getValue())):
            #                     print(i[0], i[2],
            #                           "Condition 1.2: There exists an object with the same name. Do you want to delete the existing object? Please answer Y/N: ")
            #                     ans = str(input())
            #                     # if ans == 'Y':
            #                     #     print("Condition 1.2.1")
            #                     #     # result = self.deleteTCP(i[1])
            #                     #     # if int(result) <= 299 and int(result) >= 200:
            #                     #     #     self.allPortObjectList.remove(i)
            #                     #     result = tcp.createTCP(self.authHeader)
            #                     #     if int(result) <= 299 and int(result) >= 200:
            #                     #         self.allHostObjectList.append(
            #                     #             [tcp.getName(), tcp.getUUID(), tcp.getValue(), 'TCP', tcp.getType(),
            #                     #              tcp.getDescription()])
            #                     # else:
            #                     #     print("Condition 1.2.2: Skipped this host.")
            #
            #         print(flag_tcp)
            #         if flag_tcp == True:
            #             print("Condition 2", tcp.getName())
            #             result = tcp.createTCP(self.authHeader)
            #             if int(result) <= 299 and int(result) >= 200:
            #                 self.allPortObjectList.append(
            #                     [tcp.getName(), tcp.getID(), tcp.getValue(), 'TCP', tcp.getType(),
            #                                  tcp.getDescription()])
            #             print(result)
            #
            #             print("After ports: ", self.allPortObjectList)
            # case "UDP":
            #
            #     for udp in self.udpObjectList:
            #         flag_udp = True
            #         for i in self.allPortObjectList:
            #
            #             if i[0] == udp.getName():
            #                 print("i host: ", i)
            #                 flag_udp = False
            #                 if ((i[0] == udp.getName()) and (i[2] == udp.getValue()) and i[3] == 'UDP'):
            #                     print("Exactly same object so no need to delete. Condition 1.1 ", i[0])
            #                     flag_udp = False
            #                 elif ((i[0] == udp.getName()) and (i[2] != udp.getValue())):
            #                     print(i[0], i[2],
            #                           "Condition 1.2: There exists an object with the same name. Do you want to delete the existing object? Please answer Y/N: ")
            #                     ans = str(input())
            #                     # if ans == 'Y':
            #                     #     print("Condition 1.2.1")
            #                     #     # result = self.deleteTCP(i[1])
            #                     #     # if int(result) <= 299 and int(result) >= 200:
            #                     #     #     self.allPortObjectList.remove(i)
            #                     #     result = tcp.createTCP(self.authHeader)
            #                     #     if int(result) <= 299 and int(result) >= 200:
            #                     #         self.allHostObjectList.append(
            #                     #             [tcp.getName(), tcp.getUUID(), tcp.getValue(), 'TCP', tcp.getType(),
            #                     #              tcp.getDescription()])
            #                     # else:
            #                     #     print("Condition 1.2.2: Skipped this host.")
            #
            #         print(flag_udp)
            #         if flag_udp == True:
            #             print("Condition 2", udp.getName())
            #             result = udp.createUDP(self.authHeader)
            #             if int(result) <= 299 and int(result) >= 200:
            #                 self.allPortObjectList.append(
            #                     [udp.getName(), udp.getID(), udp.getValue(), 'UDP', udp.getType(),
            #                      udp.getDescription()])
            #             print(result)
            #
            #             print("After ports: ", self.allPortObjectList)
            #
            # case "network":
            #     for network in self.networkObjectList:
            #         flag_network = True
            #         for i in self.allNetworkObjectList:
            #
            #             if i[0] == network.getName():
            #                 flag_network = False
            #                 print("1: ", flag_network)
            #                 print(i[0], "Condition 1")
            #                 print("True for ", network.getGroupMembership(), "id: ", i)
            #                 if ((i[0] == network.getName()) and (i[2] == network.getValue())):
            #                     print(
            #                         "Exactly same object so no need to delete. Condition 1.1 ", i[0])
            #                     flag_network = False
            #                 elif ((i[0] == network.getName()) and (i[2] != network.getValue())):
            #                     print(
            #                         i[0], i[2], "Condition 1.2: There exists an object with the same name. Do you want to delete the existing object? Please answer Y/N: ")
            #                     ans = str(input())
            #                     if ans == 'Y':
            #                         print("Condition 1.2.1")
            #                         result = self.deleteNetwork(i[1])
            #                         if int(result) <= 299 and int(result) >= 200:
            #                             self.allNetworkObjectList.remove(i)
            #
            #                         authHeader = {"X-auth-access-token": self.apiToken}
            #                         result = network.createNetwork(authHeader)
            #                         if int(result) <= 299 and int(result) >= 200:
            #                             self.allNetworkObjectList.append([network.getName(), network.getUUID(
            #                             ), network.getValue(), network.getType(), network.getDescription()])
            #
            #                         print("result crete network: ", result)
            #                         print("Name for: ", network.getName(),
            #                               " Id: ", network.getUUID())
            #                     else:
            #                         print(
            #                             "Condition 1.2.2: Skipped this network.")
            #
            #         print(flag_network)
            #         if flag_network == True:
            #             print("Condition 2", network.getName())
            #             authHeader = {"X-auth-access-token": self.apiToken}
            #             result = network.createNetwork(authHeader)
            #             if int(result) <= 299 and int(result) >= 200:
            #                 self.allNetworkObjectList.append([network.getName(), network.getUUID(
            #                 ), network.getValue(), network.getType(), network.getDescription()])
            #             print(result)
            #             print("Name for: ", network.getName(),
            #                   " Id: ", network.getUUID())
            #
            # case "url":
            #     for url in self.URLObjectList:
            #         flag_url = True
            #         for i in self.allUrlObjectList:
            #
            #             if i[0] == url.getName():
            #                 flag_url = False
            #                 print("1: ", flag_url)
            #                 print(i[0], "Condition 1")
            #                 # print("True for ", network.getName(), "id: ", i[1])
            #                 if ((i[0] == url.getName()) and (i[2] == url.getValue())):
            #                     print(
            #                         "Exactly same object so no need to delete. Condition 1.1 ", i[0])
            #                     flag_url = False
            #                 elif ((i[0] == url.getName()) and (i[2] != url.getValue())):
            #                     print(i[0], i[2],
            #                           "Condition 1.2: There exists an object with the same name. Do you want to delete the existing object? Please answer Y/N: ")
            #                     ans = str(input())
            #                     if ans == 'Y':
            #                         print("Condition 1.2.1")
            #                         result = self.deleteUrls(i[1])
            #                         if int(result) <= 299 and int(result) >= 200:
            #                             self.allUrlObjectList.remove(i)
            #                         result = url.createURL(self.authHeader)
            #                         if int(result) <= 299 and int(result) >= 200:
            #                             self.allUrlObjectList.append([url.getName(), url.getUUID(
            #                             ), url.getValue(), url.getType(), url.getDescription()])
            #                         print("result crete url: ", result)
            #                         print("Name for: ", url.getName(),
            #                               " Id: ", url.getUUID())
            #                     else:
            #                         print("Condition 1.2.2: Skipped this url.")
            #
            #         print(flag_url)
            #         if flag_url == True:
            #             print("Condition 2", url.getName())
            #             result = url.createURL(self.authHeader)
            #             if int(result) <= 299 and int(result) >= 200:
            #                 self.allUrlObjectList.append([url.getName(), url.getUUID(
            #                 ), url.getValue(), url.getType(), url.getDescription()])
            #             print(result)
            #             print("Name for: ", url.getName(),
            #                   " Id: ", url.getUUID())
            #
            # case "fqdn":
            #
            #     for fqdn in self.FQDNObjectList:
            #         flag_fqdn = True
            #         for i in self.allFQDNObjects:
            #
            #             if i[0] == fqdn.getName():
            #                 flag_fqdn = False
            #                 if ((i[0] ==fqdn.getName()) and (i[2] == fqdn.getValue())):
            #                     print(
            #                         "Exactly same object so no need to delete. Condition 1.1 ", i[0])
            #                     flag_fqdn = False
            #                 elif ((i[0] == fqdn.getName()) and (i[2] != fqdn.getValue())):
            #                     print(i[0], i[2],
            #                           "Condition 1.2: There exists an object with the same name. Do you want to delete the existing object? Please answer Y/N: ")
            #                     ans = str(input())
            #                     if ans == 'Y':
            #                         print("Condition 1.2.1")
            #                         result = self.deleteFQDNs(i[1])
            #                         if int(result) <= 299 and int(result) >= 200:
            #                             self.allFQDNObjects.remove(i)
            #                         result = fqdn.createFQDN(self.authHeader)
            #                         if int(result) <= 299 and int(result) >= 200:
            #                             self.allFQDNObjects.append([fqdn.getName(), fqdn.getID(
            #                             ), fqdn.getValue(), fqdn.getType(), fqdn.getDescription()])
            #                     else:
            #                         print("Condition 1.2.2: Skipped this fqdn.")
            #
            #         print(flag_fqdn)
            #         if flag_fqdn == True:
            #             print("Condition 2", fqdn.getName())
            #             result = fqdn.createFQDN(self.authHeader)
            #             if int(result) <= 299 and int(result) >= 200:
            #                 self.allFQDNObjects.append([fqdn.getName(), fqdn.getID(), fqdn.getValue(), fqdn.getType(), fqdn.getDescription()])
            #             print(result)
            #
            # case "range":
            #
            #     for range in self.rangeObjectList:
            #         flag_range = True
            #         for i in self.allRangeObjects:
            #
            #             if i[0] == range.getName():
            #                 flag_range = False
            #                 if ((i[0] == range.getName()) and (i[2] == range.getValue())):
            #                     print(
            #                         "Exactly same object so no need to delete. Condition 1.1 ", i[0])
            #                     flag_range = False
            #                 elif ((i[0] == range.getName()) and (i[2] != range.getValue())):
            #                     print(i[0], i[2],
            #                           "Condition 1.2: There exists an object with the same name. Do you want to delete the existing object? Please answer Y/N: ")
            #                     ans = str(input())
            #                     if ans == 'Y':
            #                         print("Condition 1.2.1")
            #                         result = self.deleteRange(i[1])
            #                         if int(result) <= 299 and int(result) >= 200:
            #                             self.allRangeObjects.remove(i)
            #                         result = range.createRange(self.authHeader)
            #                         if int(result) <= 299 and int(result) >= 200:
            #                             self.allRangeObjects.append([range.getName(), range.getID(
            #                             ), range.getValue(), range.getType(), range.getDescription()])
            #                     else:
            #                         print("Condition 1.2.2: Skipped this range.")
            #
            #         print(flag_range)
            #         if flag_range == True:
            #             print("Condition 2", range.getName())
            #             result = range.createRange(self.authHeader)
            #             if int(result) <= 299 and int(result) >= 200:
            #                 self.allRangeObjects.append(
            #                     [range.getName(), range.getID(), range.getValue(), range.getType(), range.getDescription()])
            #             print(result)
            #
            # case _:
            #     return None





    def __getSecurityZones(self):
        """
        Retrieves the security zones from FMC environment.
        :return: The list containing the details of all the security zones.
        """

        url = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, self.securityZoneLocation)

        securityZones = ''
        rateLimit = True
        while rateLimit:

            securityZones = requests.get(
                url=url,
                headers=self.authHeader,
                verify=False
            )

            if securityZones.status_code != 429:
                rateLimit = False
            else:
                print("429 Error - Waiting 2 seconds to resend call: " + url)
                time.sleep(2)
        returnList = []

        if securityZones.content:

            securityZones = securityZones.json()['items']

            for zone in securityZones:
                del zone['links']
                returnList.append(SecurityZones.SecurityZoneObject(
                    zone['name'], zone['id']))
        else:
            print("Security zones were not retrieved.")

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

        ports=''
        rateLimitPorts = True
        while rateLimitPorts:
            ports = requests.get(
                url=url,
                headers=self.authHeader,
                params=queryParameters,
                verify=False
            )

            if ports.status_code != 429:
                rateLimitPorts = False
            else:
                print("429 Error - Waiting 2 seconds to resend call: " + url)
                time.sleep(2)

        returnList = []
        if ports.content:
            # print(ports.content)

            ports = ports.json()['items']
            # print("All ports: ", ports)

            temp = ''

            for cat in ports:
                del cat['links']

                newUrl = buildUrlForResourceWithId(self.fmcIP, self.domainLocation, self.domainId, self.portLocation, cat['id'])

                port = ''
                rateLimitPort = True
                while rateLimitPort:

                    port = requests.get(
                        url=newUrl,
                        headers=self.authHeader,
                        verify=False
                    )

                    if port.status_code != 429:
                        rateLimitPort = False
                    else:
                        print("429 Error - Waiting 2 seconds to resend call: " + url)
                        time.sleep(2)


                if port.content:
                    

                    port = port.json()
                    


                    # if port and port["name"]:
                    #     self.logger.info("Network retrieved. {Name: " + port['name'] + ", Value: " + port['port'] + "}")
                    if 'port' in port.keys():
                        returnList.append([port['name'], port['id'],
                                           port['port'], port['protocol'], port['type'], port['description']])
                        temp = port['name']
                        
                    else:
                        print("The port ", port['name'], " does not have a port value associated with it.")
                else:
                    print("The port after", temp, "was not retrieved.")
        else:
            print("No ports retrieved.")


        # print("All ports: ", returnList)

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

        filePolicies = ''
        rateLimit = True
        while rateLimit:

            filePolicies = requests.get(
                url=url,
                headers=self.authHeader,
                verify=False
            )

            if filePolicies.status_code != 429:
                rateLimit = False
            else:
                print("429 Error - Waiting 2 seconds to resend call: " + url)
                time.sleep(2)


        returnList = []
        if filePolicies.content:

            filePolicies = filePolicies.json()['items']


            for fp in filePolicies:
                del fp['links']

                returnList.append(
                    FilePolicy.FilePolicyObject(fp['name'], fp['id']))
        else:
            print("No file policies were retrieved.")

        return returnList

    def __getURLCategories(self):
        """
        Retrieves the URL Categories from FMC environment.
        :return: The list containing the details of all the URL Categories.
        """

        url = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, self.urlCategoryLocation)
        urlCategories = ''
        rateLimit = True
        while rateLimit:

            urlCategories = requests.get(
                url=url,
                headers=self.authHeader,
                verify=False
            )

            if urlCategories.status_code != 429:
                rateLimit = False
            else:
                print("429 Error - Waiting 2 seconds to resend call: " + url)
                time.sleep(2)


        returnList = []

        if urlCategories.content:

            urlCategories = urlCategories.json()['items']

            for cat in urlCategories:
                del cat['links']

                returnList.append(
                    URLCategory.URLCategoryObject(cat['name'], cat['id']))
                # print("Name: ", cat['name'], " Id: ", cat['id'])
        else:
            print("UrlCategories were not retrieved.")

        return returnList

    def __getApplications(self):
        """
        Retrieves the Applications from FMC environment.
        :return: The list containing the details of all Applications.
        """

        url = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, self.applicationLocation)

        applications=''
        rateLimit = True
        while rateLimit:

            applications = requests.get(
                url=url,
                headers=self.authHeader,
                verify=False
            )
            if applications.status_code != 429:
                rateLimit = False
            else:
                print("429 Error - Waiting 2 seconds to resend call: " + url)
                time.sleep(2)


        returnList = []

        if applications.content:

            applications = applications.json()['items']

            for cat in applications:
                del cat['links']

                returnList.append(
                    Application.ApplicationObject(cat['name'], cat['id']))
                # print("A Name: ", cat['name'], " A Id: ", cat['id'])
        else:
            print("No applications were retrieved.")

        return returnList

    def __getAllNetworks(self):
        """
        Retrieves the Networks from FMC environment.
        :return: The list containing the details of all the Networks.
        """

        url = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, self.networkLocation)
        networks = ''

        rateLimitNws = True
        while rateLimitNws:
            networks = requests.get(
                url=url,
                headers=self.authHeader,
                verify=False
            )

            if networks.status_code != 429:
                rateLimitNws = False
            else:
                print("429 Error - Waiting 2 seconds to resend call: " + url)
                time.sleep(2)

        returnList = []


        if networks.content:
            temp = ''

            networks = networks.json()['items']

            for cat in networks:
                del cat['links']

                newUrl = buildUrlForResourceWithId(self.fmcIP, self.domainLocation, self.domainId, self.networkLocation,
                                                   cat['id'])
                network = ''

                rateLimitNw = True
                while rateLimitNw:
                    network = requests.get(
                        url=newUrl,
                        headers=self.authHeader,
                        verify=False
                    )

                    if network.status_code != 429:
                        rateLimitNw = False
                    else:
                        print("429 Error - Waiting 2 seconds to resend call: " + url)
                        time.sleep(2)

                if network.content:

                    network = network.json()

                    # if network and network["name"]:
                    #     self.logger.info("Network retrieved. {Name: " + network['name'] + ", Value: " + network['value'] + "}")
                    if 'name' in network.keys():

                        returnList.append([network['name'], network['id'],
                                           network['value'], network['type'], network['description']])
                        temp = network['name']
                else:
                    print("The object after", temp, "was not retrieved.")
        else:
            print("No network objects were retrieved.")

        return returnList

    def __getAllUrls(self):
        """
        Retrieves the URLs from FMC environment.
        :return: The list containing the details of all the URLs.
        """
        url = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, self.urlLocation)

        networks = ''

        rateLimitUrls = True
        while rateLimitUrls:
            networks = requests.get(
                url=url,
                headers=self.authHeader,
                verify=False
            )

            if networks.status_code != 429:
                rateLimitUrls = False
            else:
                print("429 Error - Waiting 2 seconds to resend call: " + url)
                time.sleep(2)


        returnList = []

        if networks.content:

            urls = networks.json()['items']
            temp = ''


            for cat in urls:
                del cat['links']

                newURL = buildUrlForResourceWithId(self.fmcIP, self.domainLocation, self.domainId, self.urlLocation,
                                                   cat['id'])

                network = ''
                rateLimitUrl = True
                while rateLimitUrl:

                    network = requests.get(
                        url=newURL,
                        headers=self.authHeader,
                        verify=False
                    )

                    if network.status_code != 429:
                        rateLimitUrl = False
                    else:
                        print("429 Error - Waiting 2 seconds to resend call: " + url)
                        time.sleep(2)


                if network.content:

                    network = network.json()
                    returnList.append(
                        [network['name'], network['id'], network['url'], network['type'], network['description']])
                    temp = network['name']
                else:
                    print("The url after", temp, "was not retrieved.")
        else:
            print("URLs were not retrieved.")
        return returnList

    def __getAllHosts(self):
        """
        Retrieves the Hosts from FMC environment.
        :return: The list containing the details of all the Hosts.
        """
        url = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, self.hostLocation)
        hosts = ''
        rateLimitHosts = True
        while rateLimitHosts:
            hosts = requests.get(
                url=url,
                headers=self.authHeader,
                verify=False
            )
            if hosts.status_code != 429:
                rateLimitHosts = False
            else:
                print("429 Error - Waiting 2 seconds to resend call: " + url)
                time.sleep(2)


        returnList = []

        if hosts.content:
            temp = ''

            hosts = hosts.json()['items']

            for cat in hosts:
                del cat['links']

                newURL = buildUrlForResourceWithId(self.fmcIP, self.domainLocation, self.domainId, self.hostLocation,
                                                   cat['id'])
                host = ''
                rateLimitHost = True
                while rateLimitHost:

                    host = requests.get(
                        url=newURL,
                        headers=self.authHeader,
                        verify=False
                    )
                    if host.status_code != 429:
                        rateLimitHost = False
                    else:
                        print("429 Error - Waiting 2 seconds to resend call: " + url)
                        time.sleep(2)


                if host.content:

                    host = host.json()
                    returnList.append(
                        [host['name'], host['id'], host['value'], host['type'], host['description']])
                    temp = host['name']
                else:
                    print("Host object after", temp, "was not retrieved.")

        else:
            print("No host objects were retrieved.")

        return returnList

    def __getAllFQDNs(self):
        """
        Retrieves the FQDNs from FMC environment.
        :return: The list containing the details of all the FQDNs.
        """
        url = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, self.fqdnLocation)

        fqdn = ''
        rateLimitFQDNs = True
        while rateLimitFQDNs:

            fqdn = requests.get(
                url=url,
                headers=self.authHeader,
                verify=False
            )
            if fqdn.status_code != 429:
                rateLimitFQDNs = False
            else:
                print("429 Error - Waiting 2 seconds to resend call: " + url)
                time.sleep(2)


        returnList = []
        temp = ''
        if fqdn.content:
            # print("FQDN all response: ", fqdn.json())
            if 'items' in fqdn.json().keys():
                fqdns = fqdn.json()['items']


                for cat in fqdns:
                    del cat['links']


                    newURL = buildUrlForResourceWithId(self.fmcIP, self.domainLocation, self.domainId, self.fqdnLocation,
                                                       cat['id'])
                    fqdn = ''
                    rateLimitFQDN = True
                    while rateLimitFQDN:

                        fqdn = requests.get(
                            url=newURL,
                            headers=self.authHeader,
                            verify=False
                        )
                        if fqdn.status_code != 429:
                            rateLimitFQDN = False
                        else:
                            print("429 Error - Waiting 2 seconds to resend call: " + url)
                            time.sleep(2)



                    if fqdn.content:

                        fqdn = fqdn.json()
                        returnList.append([fqdn['name'], fqdn['id'], fqdn['value'], fqdn['type'], fqdn['description']])
                        temp = fqdn['name']
                    else:
                        print("The FQDN after", temp, "was not retrieved.")
        else:
            print("No FQDN objects were retrieved.")

        return returnList

    def __getAllRanges(self):
        url = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, self.rangeLocation)


        range = requests.get(
            url=url,
            headers=self.authHeader,
            verify=False
        )



        returnList = []
        # print("Range all response: ", range.json())
        if range and range.json():
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
        # print("Ranges list: ", returnList)

        return returnList

    def __getNetworkGroups(self):

        url = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, self.networkGroupLocation)

        nwGroups = requests.get(
            url=url,
            headers=self.authHeader,
            verify=False
        )

        nwGroups = nwGroups.json()
        # print("NW groups: ", nwGroups)

    def __getAllGroups(self):
        """
        Retrieves the list of all the object groups from FMC environment.
        :return: The list containing details of all the groups.
        """
        url = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, self.networkGroupLocation)

        nwGroup = ''
        rateLimitNwGroups = True
        while rateLimitNwGroups:

            nwGroup = requests.get(
                url=url,
                headers=self.authHeader,
                verify=False
            )
            if nwGroup.status_code != 429:
                rateLimitNwGroups = False
            else:
                print("429 Error - Waiting 2 seconds to resend call: " + url)
                time.sleep(2)

        returnList = []
        temp = ''

        if nwGroup.content:

            nwGroup = nwGroup.json()['items']
            # print("All nw groups1: ", nwGroup)


            for cat in nwGroup:
                del cat['links']

                newUrl = buildUrlForResourceWithId(self.fmcIP, self.domainLocation, self.domainId,
                                                   self.networkGroupLocation, cat['id'])

                nw = ''
                rateLimitnw = True
                while rateLimitnw:

                    nw = requests.get(
                        url=newUrl,
                        headers=self.authHeader,
                        verify=False
                    )

                    if nw.status_code != 429:
                        rateLimitnw = False
                    else:
                        print("429 Error - Waiting 2 seconds to resend call: " + url)
                        time.sleep(2)

                if nw.content:
                    temp = cat['name']
                # print("One nw: ", nw.json())
                    if 'objects' in nw.json().keys() and 'literals' in nw.json().keys():
                        returnList.append([cat['name'], cat['id'], 'objects', cat['type'], nw.json()['objects'], 'literals', nw.json()['literals']])
                    if 'objects' in nw.json().keys() and 'literals' not in nw.json().keys():
                        returnList.append([cat['name'], cat['id'], 'objects', cat['type'], nw.json()['objects'], 'literals', []])
                    if 'objects' not in nw.json().keys() and 'literals' in nw.json().keys():
                        returnList.append([cat['name'], cat['id'], 'objects', cat['type'], [], 'literals', nw.json()['literals']])
                    if 'objects' not in nw.json().keys() and 'literals' not in nw.json().keys():
                        returnList.append([cat['name'], cat['id'], 'objects', cat['type'], [], 'literals', []])
                else:
                    print("The network group after", temp, "was not retrieved.")
        else:
            print("No network group was retrieved.")

        url2 = buildUrlForResource(self.fmcIP, self.domainLocation, self.domainId, self.urlGroupLocation)

        nwGroup = ''
        rateLimitnw = True
        while rateLimitnw:

            nwGroup = requests.get(
                url=url2,
                headers=self.authHeader,
                verify=False
            )

            if nwGroup.status_code != 429:
                rateLimitnw = False
            else:
                print("429 Error - Waiting 2 seconds to resend call: " + url)
                time.sleep(2)

        if nwGroup.content:
            temp = ''
            if 'items' in nwGroup.json().keys():
                urlGroup = nwGroup.json()['items']
                # returnList = []

                for cat in urlGroup:
                    del cat['links']

                    newUrl = buildUrlForResourceWithId(self.fmcIP, self.domainLocation, self.domainId,
                                                       self.urlGroupLocation, cat['id'])

                    nw=''
                    rateLimitnw = True
                    while rateLimitnw:

                        nw = requests.get(
                            url=newUrl,
                            headers=self.authHeader,
                            verify=False
                        )

                        if nw.status_code != 429:
                            rateLimitnw = False
                        else:
                            print("429 Error - Waiting 2 seconds to resend call: " + url)
                            time.sleep(2)

                    if nw.content:
                        temp = cat['name']
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
                    else:
                        print("The url group after", temp, "was not retrieved.")
        else:
            print("No URL groups were retrieved.")
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
        # print("All groups: ", self.allGroupsList)
        for i in self.allGroupsList:
            # print("type", i[3])
            if i[3] == 'NetworkGroup':
                networks.append([i[0], i[1], i[4], i[3], ''])

        return networks
    def mergeURLwithURLGroups(self):
        urls = self.allUrlObjectList
        # print("Before merging: ", urls)

        for i in self.allGroupsList:
            # print("type url", i[3])
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
        # print("Merged networks: ", allNetworks)
        # print("Merged urlS: ", allUrls)

        policyObject = AccessPolicy.AccessPolicyObject.FMCAccessPolicyObject(self, '005056B6-DCA2-0ed3-0000-017179871248', self.securityZoneObjectList, allNetworks,
                                                       self.allPortObjectList, self.filePolicyObjectList, self.urlCategoryObjectList, allUrls, self.allGroupsList, self.applicationObjectList, ruleCategory)
        
        response = policyObject.createPolicy(self.authHeader, csvRow, ruleCategory)

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




