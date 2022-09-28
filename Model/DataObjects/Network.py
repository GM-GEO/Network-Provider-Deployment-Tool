from typing import Dict
import requests

from Model.Providers.FMCConfig import FMC
from Model.Providers.PaloAltoConfig import PaloAlto
from Model.Providers.Provider import buildUrlForResource
from Model.Utilities.LoggingUtils import Logger_GetLogger


class NetworkObject:

    #optional parameters
    overridable = False

    def __init__(self, resourceURL, groupMembership, postBody,
                 queryParameters: Dict):

        self.creationURL = resourceURL
        self.objectPostBody = postBody
        self.objectUUID = ''
        self.groupMembership = groupMembership

        if queryParameters:
            self.queryParameters = queryParameters
            pass

    @classmethod
    def FMCNetwork(cls, provider: FMC, name, value, description,
                   groupMembership):

        objectPostBody = {}

        objectPostBody['name'] = name
        objectPostBody['type'] = 'network'
        objectPostBody['value'] = value
        objectPostBody['description'] = description

        url = buildUrlForResource(provider.fmcIP, provider.domainLocation,
                                  provider.domainId, provider.networkLocation)

        return cls(url, name, value, description, groupMembership,
                   objectPostBody, None)

    @classmethod
    def PaloAltNetwork(cls, provider: PaloAlto, name, value, description,
                       groupMembership):

        objectPostBody = {}

        objectPostBody['name'] = name
        objectPostBody['type'] = 'network'
        objectPostBody['value'] = value
        objectPostBody['description'] = description

        url = buildUrlForResource(provider.fmcIP, provider.domainLocation,
                                  provider.domainId, provider.objectLocation)

        return cls(url, name, value, description, groupMembership,
                   objectPostBody)

    def createNetwork(self, apiToken):
        # Set authentication in the header

        logger = Logger_GetLogger()
        authHeaders = {"X-auth-access-token": apiToken}

        response = requests.post(url=self.creationURL,
                                 headers=authHeaders,
                                 json=self.objectPostBody,
                                 verify=False)
        print("URL: ", response.url)

        if response.status_code <= 299 and response.status_code >= 200:
            self.objectUUID = response.json()['id']
            logger.info("Created Network Object: {" + self.getName() +
                        " Type: " + self.getType() + "}")

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