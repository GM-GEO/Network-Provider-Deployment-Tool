from typing import Dict
import requests
from Model.DataObjects.Enums.ObjectTypeEnum import ObjectTypeEnum

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

        self.queryParameters = queryParameters

    @classmethod
    def FMCNetwork(cls, provider: FMC, name, value, description,
                   groupMembership):

        objectPostBody = {}

        objectPostBody['name'] = name
        objectPostBody['type'] = ObjectTypeEnum.NETWORK.value
        objectPostBody['value'] = value
        objectPostBody['description'] = description

        url = buildUrlForResource(provider.fmcIP, provider.domainLocation,
                                  provider.domainId, provider.networkLocation)

        queryParameters = {}
        return cls(url, groupMembership, objectPostBody, queryParameters)

    @classmethod
    def PaloAltNetwork(cls, provider: PaloAlto, name, value, description,
                       groupMembership):

        objectPostBody = {}
        objectPostBody['entry'] = {}

        objectPostBody['entry']['@name'] = name
        objectPostBody['entry']['@location'] = 'vsys'
        objectPostBody['entry']['@vsys'] = 'vsys1'
        objectPostBody['entry']['ip-netmask'] = value
        print("Body: ", objectPostBody)

        queryParameters = {}
        queryParameters['name'] = name
        queryParameters['location'] = 'vsys'
        queryParameters['vsys'] = 'vsys1'

        url = buildUrlForResource(provider.paloAltoIP, provider.domainLocation,
                                  '', provider.networkLocation)

        return cls(url, groupMembership, objectPostBody, queryParameters)

    def createNetwork(self, apiToken):
        # Set authentication in the header

        logger = Logger_GetLogger()
        # authHeaders = {"X-auth-access-token": apiToken}
        # authHeaders = {"X-PAN-KEY": apiToken}
        print("ApiToken for NW creation: ", apiToken)

        response = requests.post(url=self.creationURL,
                                 headers=apiToken,
                                 params=self.queryParameters,
                                 json=self.objectPostBody,
                                 verify=False)
        print("Response: ", response.json())

        if response.status_code <= 299 and response.status_code >= 200:
            if 'id' in response.json().keys():
                self.objectUUID = response.json()['id']
            # logger.info("Created Network Object: {" + self.getPName() +
            #             " Type: " + self.getType() + "}")

        return response.status_code

    def getUUID(self):
        return self.objectUUID

    def getName(self):
        return self.objectPostBody['name']

    def getPName(self):
        return self.objectPostBody['entry']['@name']

    def getType(self):
        return self.objectPostBody['type']

    def getValue(self):
        return self.objectPostBody['value']

    def getPValue(self):
        return self.objectPostBody['entry']['ip-netmask']

    def getDescription(self):
        return self.objectPostBody['description']

    def getGroupMembership(self):
        return self.groupMembership
