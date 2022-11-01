from typing import Dict
import requests
import time
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
        """

        :param resourceURL:
        :param groupMembership: The group that a Network object belongs to.
        :param postBody: Body to be passed while making the post request for creating a Network object.
        :param queryParameters: Query parameters to pass while making a post request.
        """

        self.creationURL = resourceURL
        self.objectPostBody = postBody
        self.objectUUID = ''
        self.groupMembership = groupMembership

        self.queryParameters = queryParameters

    @classmethod
    def FMCNetwork(cls, provider: FMC, name, value, description,
                   groupMembership):
        """
        Constructor for FMC Network object.
        :param provider: FMC in this case
        :param name: Name of the Network object.
        :param value: Value of the Network object
        :param description:
        :param groupMembership: Group name the Network object falls in.
        :return:
        """

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
    def PaloAltoNetwork(cls, provider: PaloAlto, name, value, description,
                       groupMembership):
        """
        Constructor for the Palo Alto Network object.
        :param provider: Palo Alto in this case.
        :param name: Name of Palo Alto Network object.
        :param value: Value of the Palo Alto Network object.
        :param description:
        :param groupMembership: Group name the Network object falls in.
        :return:
        """

        print("Reaching here")

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
        print("URL test: ", url)

        return cls(url, groupMembership, objectPostBody, queryParameters)

    def createNetwork(self, apiToken):
        """
        Makes a POST request to create a Network object.
        :param apiToken: Authentication token
        :return: The status code of the response received from the api call.
        """
        logger = Logger_GetLogger()

        # print("ApiToken for NW creation: ", apiToken)
        rateLimit = True
        response=''
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
