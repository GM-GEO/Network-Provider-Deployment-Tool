from typing import Dict
import requests
import time
from requests.auth import HTTPBasicAuth
import csv
from collections import OrderedDict
from Model.Providers.FMCConfig import FMC
from Model.Providers.PaloAltoConfig import PaloAlto
from Model.Providers.Provider import buildUrlForResource


class HostObject:
    # base set of attributes

    # optional attributes
    overridable = False

    def __init__(self, resourceURL, groupMembership, postBody,
                 queryParameters: Dict, groupDescription):
        """

        :param resourceURL: The url to be used for making the API call.
        :param groupMembership: The group name of the Host object.
        :param postBody: The body to be passed while making the post requests.
        :param queryParameters: The parameters to be passed for the api post request.
        """
        self.creationURL = resourceURL
        self.objectPostBody = postBody
        self.objectUUID = ''
        self.groupMembership = groupMembership

        self.queryParameters = queryParameters
        self.groupDescription = groupDescription

    @classmethod
    def FMCHost(cls, provider: FMC, name: str, value: str, description: str,
                groupMembership: str, groupDescription: str):
        """
        Creates a constructor for adding FMC hosts.
        :param provider: FMC in this case.
        :param name: The name of the Host object.
        :param value: Value of the Host object.
        :param description: The description of the Host object.
        :param groupMembership: The group name of the host object.
        :return:
        """

        objectPostBody = {}
        objectPostBody['name'] = name
        objectPostBody['type'] = 'host'
        objectPostBody['value'] = value
        objectPostBody['description'] = description

        url = buildUrlForResource(provider.fmcIP, provider.domainLocation, provider.domainId,
                                  provider.hostLocation)

        queryParameters = {}

        return cls(url, groupMembership, objectPostBody, queryParameters, groupDescription)

    @classmethod
    def PaloAltoHost(cls, provider: PaloAlto, name: str, value: str,
                     description: str, groupMembership: str):
        """
       Creates a constructor for adding Palo Alto hosts.
       :param provider: Palo Alto in this case.
       :param name: The name of the Host object.
       :param value: Value of the Host object.
       :param description: The description of the Host object.
       :param groupMembership: The group name of the host object.
       :return:
       """

        objectPostBody = {}
        objectPostBody['entry'] = {}

        objectPostBody['entry']['@name'] = name
        objectPostBody['entry']['@location'] = 'vsys'
        objectPostBody['entry']['@vsys'] = 'vsys1'
        objectPostBody['entry']['ip-netmask'] = value

        queryParameters = {}
        queryParameters['name'] = name
        queryParameters['location'] = 'vsys'
        queryParameters['vsys'] = 'vsys1'

        url = buildUrlForResource(provider.paloAltoIP, provider.domainLocation,
                                  '', provider.networkLocation)

        return cls(url, groupMembership, objectPostBody, queryParameters)

    def createHost(self, apiToken):
        """
        Initiates a POST request to create a Host object in the provider environment, which can be either FMC or Palo Alto.
        :param apiToken: The authentication token to add in the headers.
        :return: The status code of the response received from the api call.
        """
        # print("ApiToken for Host creation: ", apiToken)
        response=''
        rateLimit=True
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

        # print("Response: ", response.json())

        if response.status_code <= 299 and response.status_code >= 200:
            if 'id' in response.json().keys():
                self.objectUUID = response.json()['id']
            # logger.info("Created Network Object: {" + self.getPName() +
            #             " Type: " + self.getType() + "}")

        return response.status_code

    def createFMCHost(self, apiToken):
        # set authentication in the header
        # authHeaders = {"X-auth-access-token": apiToken}

        response = requests.post(url=self.creationURL,
                                 headers=apiToken,
                                 json=self.objectPostBody,
                                 verify=False)

        # print(response.json()['id'])

        if response.status_code <= 299 and response.status_code >= 200:
            if 'id' in response.json().keys():
                self.objectUUID = response.json()['id']
            # print("Id: ", self.objectUUID)

        # print("Host body: ", response.json())

        # self.getAllHosts(self.apiToken)
        # print(response.json()['error']['messages'][0]['description'])
        #
        # return ("Error: ", response.json()['error']['messages'][0]['description'])

        return response.status_code

    def createPaloAltoHost(self, apiToken):
        # set authentication in the header
        # authHeaders = {"X-auth-access-token": apiToken}

        response = requests.post(url=self.creationURL,
                                 headers=apiToken,
                                 params=self.queryParameters,
                                 json=self.objectPostBody,
                                 verify=False)

        # print(response.json()['id'])

        if response.status_code <= 299 and response.status_code >= 200:
            if 'id' in response.json().keys():
                self.objectUUID = response.json()['id']
            # print("Id: ", self.objectUUID)

        print("Host body: ", response.json())

        # self.getAllHosts(self.apiToken)
        # print(response.json()['error']['messages'][0]['description'])
        #
        # return ("Error: ", response.json()['error']['messages'][0]['description'])

        return response.status_code

    def getAllHosts(self, apiToken):
        # Set authentication in the header
        autheHeaders = {"X-auth-access-token": apiToken}

        response = requests.get(url=self.creationURL,
                                headers=autheHeaders,
                                verify=False)
        allHosts = []
        if response.status_code <= 299 and response.status_code >= 200:
            # self.objectUUID = response.json()['id']
            for key, value in response.json()['items']:
                allHosts.append([
                    response.json()['items']['name'],
                    [response.json()['items']['id']]
                ])
            print(allHosts)

    def getUUID(self):
        """
        :return: UUID of the FMC Host object.
        """
        return self.objectUUID


    def getName(self):
        """
        :return: Name of the FMC Host object.
        """
        return self.objectPostBody['name']

    def getPName(self):
        """
        :return: Name of the Palo Alto host
        """
        return self.objectPostBody['entry']['@name']

    def getType(self):
        """
        :return: Type of the FMC object.
        """
        return self.objectPostBody['type']

    def getGroupMembership(self):
        """
        :return: Group of the FMC object.
        """
        return self.groupMembership

    def getGroupDescription(self):
        """

        :return: Description of the group.
        """
        return self.groupDescription

    def getValue(self):
        """
        :return: Value of FMC Host
        """
        return self.objectPostBody['value']

    def getPValue(self):
        """
        :return: Value of Palo Alto Host.
        """
        return self.objectPostBody['entry']['ip-netmask']

    def getDescription(self):
        """
        :return: Description og FMC object.
        """
        return self.objectPostBody['description']