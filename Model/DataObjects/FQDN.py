import requests

from Model.Providers.FMCConfig import FMC
from Model.Providers.PaloAltoConfig import PaloAlto
from Model.Providers.Provider import buildUrlForResource
from Model.Utilities.LoggingUtils import Logger_GetLogger


class FQDNObject:

    def __init__(self, resourceUrl, name, value, description, groupMembership):

        self.creationURL = resourceUrl

        self.objectUUID = ''
        self.groupMembership = groupMembership
        self.objectPostBody = {}

        self.objectPostBody['name'] = name
        self.objectPostBody['type'] = 'fqdn'
        self.objectPostBody['value'] = value
        self.objectPostBody['description'] = description

    @classmethod
    def FMCFQDN(cls, provider: FMC, name, value, description, groupMembership):

        url = buildUrlForResource(provider.fmcIP, provider.domainLocation,
                                  provider.domainId, provider.objectLocation)

        return cls(url, name, value, description, groupMembership)

    @classmethod
    def PaloAltoFQDN(cls, provider: FMC, name, value, description, groupMembership):

        url = buildUrlForResource(provider.fmcIP, provider.domainLocation,
                                  provider.domainId, provider.objectLocation)

        return cls(url, name, value, description, groupMembership)

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