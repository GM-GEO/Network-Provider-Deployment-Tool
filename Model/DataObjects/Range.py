from typing import Dict
import requests
import time
from Model.Providers.FMCConfig import FMC
from Model.Providers.PaloAltoConfig import PaloAlto
from Model.Providers.Provider import buildUrlForResource
from Model.Utilities.LoggingUtils import Logger_GetLogger


class RangeObject:

    def __init__(self, resourceUrl, groupMembership, postBody,
                 queryParameters: Dict, groupDescription):

        self.creationURL = resourceUrl
        self.objectPostBody = postBody
        self.objectUUID = ''
        self.groupMembership = groupMembership

        self.queryParameters = queryParameters
        self.groupDescription = groupDescription

    @classmethod
    def FMCRange(cls, provider: FMC, name, value, description, groupMembership, groupDescription):

        objectPostBody = {}
        objectPostBody['name'] = name
        objectPostBody['type'] = 'Range'
        objectPostBody['value'] = value
        objectPostBody['description'] = description

        url = buildUrlForResource(provider.fmcIP, provider.domainLocation,
                                  provider.domainId, provider.rangeLocation)

        queryParameters = {}
        return cls(url, groupMembership, objectPostBody, queryParameters, groupDescription)

    # @classmethod
    # def PaloAltoRange(cls, provider: PaloAlto, name, value, description,
    #                  groupMembership):
    #
    #     objectPostBody = {}
    #     objectPostBody['entry'] = {}
    #
    #     objectPostBody['entry']['@name'] = name
    #     objectPostBody['entry']['@location'] = 'vsys'
    #     objectPostBody['entry']['@vsys'] = 'vsys1'
    #     objectPostBody['entry']['fqdn'] = value
    #
    #     queryParameters = {}
    #     queryParameters['name'] = name
    #     queryParameters['location'] = 'vsys'
    #     queryParameters['vsys'] = 'vsys1'
    #
    #     url = buildUrlForResource(provider.paloAltoIP, provider.domainLocation,
    #                               '', provider.networkLocation)
    #
    #     return cls(url, groupMembership, objectPostBody, queryParameters)

    def createRange(self, apiToken):
        # set authentication in the header
        # authHeaders = {"X-auth-access-token": apiToken}
        response=''
        rateLimit = True
        while rateLimit:

            response = requests.post(url=self.creationURL,
                                     headers=apiToken,
                                     params=self.queryParameters,
                                     json=self.objectPostBody,
                                     verify=False)
            if response.status_code != 429:
                rateLimit = False
            else:
                print("429 Error - Waiting 2 seconds to resend call: " + self.creationURL)
                time.sleep(2)

        if response.status_code <= 299 and response.status_code >= 200:
            if 'id' in response.json().keys():
                self.objectUUID = response.json()['id']

        print("Range response: ", response.json())

        return response.status_code

    def getName(self):
        return self.objectPostBody['name']

    def getPName(self):
        return self.objectPostBody['entry']['@name']

    def getPValue(self):
        return self.objectPostBody['entry']['fqdn']

    def getValue(self):
        return self.objectPostBody['value']

    def getDescription(self):
        return self.objectPostBody['description']

    def getID(self):
        return self.objectUUID

    def getGroupMembership(self):
        return self.groupMembership

    def getGroupDescription(self):
        return self.groupDescription

    def getType(self):
        return self.objectPostBody['type']