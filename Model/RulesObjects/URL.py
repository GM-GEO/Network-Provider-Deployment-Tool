from typing import Dict
import requests

from Model.Providers.FMCConfig import FMC
from Model.Providers.PaloAltoConfig import PaloAlto
from Model.Providers.Provider import buildUrlForResource
from Model.Utilities.LoggingUtils import Logger_GetLogger


class URLObject:

    def __init__(self, resourceUrl, groupMembership, postBody,
                 queryParameters: Dict):

        self.creationURL = resourceUrl
        self.objectPostBody = postBody
        self.objectUUID = ''
        self.groupMembership = groupMembership

        if queryParameters:
            self.queryParameters = queryParameters
            pass

    @classmethod
    def FMCUrlObject(cls, provider: FMC, name, value, description,
                     groupMembership):

        objectPostBody = {}
        objectPostBody['name'] = name
        objectPostBody['type'] = 'url'
        objectPostBody['url'] = value
        objectPostBody['description'] = description

        url = buildUrlForResource(provider.fmcIP, provider.domainLocation,
                                  provider.domainId, provider.urlLocation)

        return cls(url, groupMembership, objectPostBody, None)

    @classmethod
    def PaloAltoUrlObject(cls, provider: FMC, name, value, description,
                          groupMembership):

        objectPostBody = {}
        objectPostBody['name'] = name
        objectPostBody['type'] = 'url'
        objectPostBody['url'] = value
        objectPostBody['description'] = description

        url = buildUrlForResource(provider.fmcIP, provider.domainLocation,
                                  provider.domainId, provider.urlLocation)

        return cls(url, groupMembership, objectPostBody, None)

    def createURL(self, apiToken):
        #Setting authentication in header
        authHeaders = {"X-auth-access-token": apiToken}
        logger = Logger_GetLogger()

        response = requests.post(url=self.creationURL,
                                 headers=authHeaders,
                                 json=self.objectPostBody,
                                 verify=False)

        if response.status_code <= 299 and response.status_code >= 200:
            logger.info(
                "URL object created within successful status range. {Status Code"
                + str(response.status_code) + "}")
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