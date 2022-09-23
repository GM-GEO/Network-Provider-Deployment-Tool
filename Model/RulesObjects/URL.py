import requests

class URLObject:

    def __init__(self, domainUUID, name, value, description, groupMembership, ip):

        self.creationURL = 'https://'+ ip +'/api/fmc_config/v1/domain/' + domainUUID + '/object/urls'

        self.objectUUID = ''
        self.groupMembership = groupMembership
        self.objectPostBody = {}

        self.objectPostBody['name'] = name
        self.objectPostBody['type'] = 'url'
        self.objectPostBody['url'] = value
        self.objectPostBody['description'] = description


    def createURL(self, apiToken):
        #Setting authentication in header
        authHeaders = {"X-auth-access-token": apiToken}

        response = requests.post(
            url = self.creationURL,
            headers = authHeaders,
            json = self.objectPostBody,
            verify = False
        )

        if response.status_code <= 299 and response.status_code >= 200:
            self.objectUUID = response.json()['id']

        return response.status_code

    def getUUID(self):
        return self.objectUUID

    def getName(self):
        return self.objectPostBody['name']

    def getValue(self):
        return self.objectPostBody['url']

    def getType(self):
        return self.objectPostBody['type']

    def getDescription(self):
        return self.objectPostBody['description']

    def getGroupMembership(self):
        return self.groupMembership