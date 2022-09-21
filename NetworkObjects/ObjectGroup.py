import requests

class GroupObject:

    def __init__(self, domainUUID, name, groupType, groupMemberIDList, ip):

        self.creationURL = 'https://'+ ip +'/api/fmc_config/v1/domain/' + domainUUID + '/object/' + groupType + "groups"

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
        #Set authentication in the header
        authHeaders = {"X-auth-access-token" : apiToken}

        response = requests.post(
            url = self.creationURL,
            headers = authHeaders,
            json = self.postBody,
            verify = False
        )

        if response.status_code <= 299 and response.status_code >= 200:
            self.groupUUID = response.json()['id']

        print("Group creation response: ", response.json())

        # print(response.json()['error']['messages'][0]['description'])

        return response.status_code


    def getName(self):
        return self.name

    def getUUID(self):
        return self.groupUUID