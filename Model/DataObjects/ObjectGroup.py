import json
import requests
import time
from Model.DataObjects.Enums.GroupTypeEnum import GroupTypeEnum
from Model.Utilities.ListUtils import contains
from Model.Utilities.LoggingUtils import Logger_GetLogger
from Model.Providers.Provider import buildUrlForResource, buildUrlForResourceWithId
from Model.Providers.FMCConfig import FMC



class GroupObject:

    def __init__(self, domainUUID, name, groupType, groupMemberIDList, ip):
        """

        :param domainUUID:
        :param name: Name of the object group.
        :param groupType: Specifies if it is a UrlGroup or a NetworkGroup.
        :param groupMemberIDList: The list of objects to be added in the object group.
        :param ip:
        """

        self.creationURL = 'https://' + ip + '/api/fmc_config/v1/domain/' + domainUUID + '/object/' + groupType + "groups"

        self.groupUUID = ''

        self.name = name

        self.groupType = groupType
        print(self.groupType)
        self.memberList = groupMemberIDList

        self.postBody = {}
        self.postBody['name'] = self.name
        self.postBody['objects'] = self.memberList

        if groupType == 'url':
            self.postBody['type'] = "UrlGroup"
        else:
            self.postBody['type'] = "NetworkGroup"

    def createGroup(self, authHeader):
        """
        Creates the group object.
        :param apiToken: The authentication token
        :return: The status code from the response received after making post request to create the object group.
        """

        logger = Logger_GetLogger()

        #Set authentication in the header
        # authHeaders = {"X-auth-access-token": apiToken}
        rateLimit = True
        response=''
        while rateLimit:

            response = requests.post(url=self.creationURL,
                                     headers=authHeader,
                                     json=self.postBody,
                                     verify=False)
            if response.status_code != 429:
                rateLimit = False
            else:
                print("429 Error - Waiting 2 seconds to resend call: " + self.creationURL)
                time.sleep(2)


        if response.status_code <= 299 and response.status_code >= 200:
            self.groupUUID = response.json()['id']
            logger.info("Group created successfully. {" + self.groupUUID + "}")
        # print(response.json()['error']['messages'][0]['description'])

        return response.status_code

    def modifyGroup(self, authHeaders, id):
        """
        Makes a put request for object groups and add additional objects in already existing groups.
        :param apiToken: Authentication token
        :param id: The id of the group object to be modified.
        :return: The status code from the response received after making post request to create the object group.
        """
        logger = Logger_GetLogger()

        url = ''
        if self.groupType == 'url':
            url = 'https://10.255.20.10/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/urlgroups/'+id
        else:
            url = 'https://10.255.20.10/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkgroups/'+id

        postBody = {}
        postBody['name'] = self.name
        postBody['id'] = id
        postBody['objects'] = self.memberList[0]
        if self.memberList[1] != []:
            postBody['literals'] = self.memberList[1]

        if self.groupType == 'url':
            postBody['type'] = "UrlGroup"
        else:
            postBody['type'] = "NetworkGroup"


        # Set authentication in the header
        # authHeaders = {"X-auth-access-token": apiToken}

        print("Inputs: ", authHeaders, url, postBody)

        response = requests.put(url=url,
                                headers=authHeaders,
                                json=postBody,
                                verify=False)

        if response.status_code <= 299 and response.status_code >= 200:
            self.groupUUID = response.json()['id']
            logger.info("Group created successfully. {" + self.groupUUID + "}")

        print("Modify response: ", response.status_code, response.json())

    def getName(self):
        """
        :return: Name of the FMC object group
        """
        return self.name

    def getUUID(self):
        """
        :return: ID of the object group
        """
        return self.groupUUID

    def getGroupMembership(self):
        return self.groupType


    def checkIfGroupExists(groupName: str, ipAddress, domainLocation, domainId,
                           apiToken):
        """
        Checks the returned list of groups to see if we have a group with the same name in the list

        Args:
            groupName (str): The group to check
            apiToken (obj): The API token to make the request with

        Returns:
            Bool: Returns if the group name was found in the list of returned objects
        """
        logger = Logger_GetLogger()
        groupTypeList = ["host", "network", "url"]
        groupExists = False
        authHeaders = {"X-auth-access-token": apiToken}

        for groupType in groupTypeList:
            logger.info("Checking Group Types for Group. {Group Name: " +
                        groupName + ", Group Type: " + groupType + "}")
            url = 'https://' + ipAddress + domainLocation + domainId + '/object/' + groupType + "groups"
            response = requests.get(url=url, headers=authHeaders, verify=False)

            if response.status_code <= 299 and response.status_code >= 200:
                groups = response.json()['items']
                if contains(groups, lambda x: x["name"] == groupName):
                    logger.info("Group found. {Group Name: " + groupName +
                                ", Group Type: " + groupType + "}")
                    groupExists = True
                    break

        return groupExists

    def createNewGroup(groupName: str, groupType: GroupTypeEnum, ipAddress,
                       domainLocation, domainId, apiToken):
        """
        Creates a new object group
        :param groupType: Specifies if it is a NetworkGroup or UrlGroup
        :param ipAddress: FMC ip address
        :param domainLocation:
        :param domainId:
        :param apiToken: Authentication token
        :return:
        """

        postBody = {}
        postBody['name'] = groupName
        postBody['type'] = groupType
        postBody['objects'] = []
        postBody['literals'] = []

        url = 'https://' + ipAddress + domainLocation + domainId + '/object/' + str(groupType).lower() + "s"
        authHeaders = {"X-auth-access-token": apiToken}

        response = requests.post(url=url,
                                 headers=authHeaders,
                                 json=postBody,
                                 verify=False)

        return response.status_code
