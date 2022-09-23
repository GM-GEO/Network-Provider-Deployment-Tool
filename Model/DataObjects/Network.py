import requests


class NetworkObject:

    #optional parameters
    overridable = False

    def __init__(self, domainUUID, name, value, description, groupMembership, ip):

        self.creationURL = 'https://'+ ip +'/api/fmc_config/v1/domain/' + domainUUID + '/object/networks'

        self.objectUUID = ''
        self.groupMembership = groupMembership
        self.objectPostBody = {}

        self.objectPostBody['name'] = name
        self.objectPostBody['type'] = 'network'
        self.objectPostBody['value'] = value
        self.objectPostBody['description'] = description


    def createNetwork(self, apiToken):
        # Set authentication in the header

        authHeaders = {"X-auth-access-token" : apiToken}

        response = requests.post(
            url = self.creationURL,
            headers = authHeaders,
            json = self.objectPostBody,
            verify = False
        )
        print("URL: ", response.url)

        if response.status_code <= 299 and response.status_code >= 200:
            self.objectUUID = response.json()['id']
            # print("Network id: ", self.objectUUID)

        print("Create network json: ", response.json())

        return response.status_code

    def getUUID(self):
        return self.objectUUID

    def getName(self):
        return self.objectPostBody['name']

    def getType(self):
        return self.objectPostBody['type']

    def getValue(self):
        return self.objectPostBody['value']

    def getDescription(self):
        return self.objectPostBody['description']

    def getGroupMembership(self):
        return self.groupMembership