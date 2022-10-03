import json
import requests
from Model.DataObjects.Enums.GroupTypeEnum import GroupTypeEnum
from Model.Utilities.ListUtils import contains
from Model.Utilities.LoggingUtils import Logger_GetLogger


class GroupObject:

    def __init__(self, domainUUID, name, groupType, groupMemberIDList, ip):

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

    def createGroup(self, apiToken):

        logger = Logger_GetLogger()

        #Set authentication in the header
        authHeaders = {"X-auth-access-token": apiToken}

        response = requests.post(url=self.creationURL,
                                 headers=authHeaders,
                                 json=self.postBody,
                                 verify=False)

        if response.status_code <= 299 and response.status_code >= 200:
            self.groupUUID = response.json()['id']
            logger.info("Group created successfully. {" + self.groupUUID + "}")
        # print(response.json()['error']['messages'][0]['description'])

        return response.status_code

    def getName(self):
        return self.name

    def getUUID(self):
        return self.groupUUID

    def checkIfGroupExists(groupName: str, ipAddress, domainLocation, domainId,
                           apiToken):
        """Checks the returned list of groups to see if we have a group with the same name in the list

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
