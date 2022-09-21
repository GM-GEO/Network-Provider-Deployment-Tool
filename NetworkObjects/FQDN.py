import requests


class FQDNObject:

    def __init__(self, domainUUID, name, value, description, groupMembership,
                 ip):

        self.creationURL = 'https://' + ip + '/api/fmc_config/v1/domain/' + domainUUID + '/object/fqdns'

        self.objectUUID = ''
        self.groupMembership = groupMembership
        self.objectPostBody = {}

        self.objectPostBody['name'] = name
        self.objectPostBody['type'] = 'fqdn'
        self.objectPostBody['value'] = value
        self.objectPostBody['description'] = description

    def createFQDN(self, apiToken):
        #set authentication in the header
        authHeaders = {"X-auth-access-token": apiToken}

        response = requests.post(url=self.creationURL,
                                 headers=authHeaders,
                                 json=self.objectPostBody,
                                 verify=False)

        if response.status_code <= 299 and response.status_code >= 200:
            self.objectUUID = response.json()['id']

        return response.status_code

    def getName(self):
        return self.objectPostBody['name']

    def getID(self):
        return self.objectUUID

    def getGroupMembership(self):
        return self.groupMembership