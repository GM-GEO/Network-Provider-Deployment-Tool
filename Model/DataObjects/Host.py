from typing import Dict
import requests
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
                 queryParameters: Dict):
        self.creationURL = resourceURL
        self.objectPostBody = postBody
        self.objectUUID = ''
        self.groupMembership = groupMembership

        self.queryParameters = queryParameters

        # if queryParameters:
        #     self.queryParameters = queryParameters
        #     pass

    @classmethod
    def FMCHost(cls, provider: FMC, name: str, value: str, description: str,
                groupMembership: str):

        objectPostBody = {}
        objectPostBody['name'] = name
        objectPostBody['type'] = 'host'
        objectPostBody['value'] = value
        objectPostBody['description'] = description

        url = buildUrlForResource(provider.fmcIP, provider.domainLocation, '',
                                  provider.networkLocation)

        queryParameters = {}

        return cls(url, groupMembership, objectPostBody, queryParameters)

    @classmethod
    def PaloAltoHost(cls, provider: PaloAlto, name: str, value: str,
                     description: str, groupMembership: str):

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
        # Set authentication in the header

        # authHeaders = {"X-auth-access-token": apiToken}
        # authHeaders = {"X-PAN-KEY": apiToken}
        print("ApiToken for Host creation: ", apiToken)

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

        print("Host body: ", response.json())

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
        return self.objectUUID
        """_summary_
        """

    def getName(self):
        return self.objectPostBody['name']

    def getPName(self):
        return self.objectPostBody['entry']['@name']

    def getType(self):
        return self.objectPostBody['type']

    def getGroupMembership(self):
        return self.groupMembership

    def getValue(self):
        return self.objectPostBody['value']

    def getPValue(self):
        return self.objectPostBody['entry']['ip-netmask']

    def getDescription(self):
        return self.objectPostBody['description']