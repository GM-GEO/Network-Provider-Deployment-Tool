import requests
from requests.auth import HTTPBasicAuth
import csv
from collections import OrderedDict


class HostObject:
    # base set of attributes

    # optional attributes
    overridable = False

    def __init__(self, domainUUID, name, value, description, groupMembership, ip):

        self.creationURL = 'https://' + ip + '/api/fmc_config/v1/domain/' + domainUUID + '/object/hosts'

        self.objectUUID = ''
        self.groupMembership = groupMembership
        self.objectPostBody = {}

        self.objectPostBody['name'] = name
        self.objectPostBody['type'] = 'host'
        self.objectPostBody['value'] = value
        self.objectPostBody['description'] = description

    def createHost(self, apiToken):
        # set authentication in the header
        autheHeaders = {"X-auth-access-token": apiToken}

        response = requests.post(
            url=self.creationURL,
            headers=autheHeaders,
            json=self.objectPostBody,
            verify=False
        )

        # print(response.json()['id'])

        if response.status_code <= 299 and response.status_code >= 200:
            self.objectUUID = response.json()['id']
            # print("Id: ", self.objectUUID)

        # self.getAllHosts(self.apiToken)
        # print(response.json()['error']['messages'][0]['description'])
        #
        # return ("Error: ", response.json()['error']['messages'][0]['description'])

        return response.status_code

    def getAllHosts(self, apiToken):
        # Set authentication in the header
        autheHeaders = {"X-auth-access-token": apiToken}

        response = requests.get(
            url=self.creationURL,
            headers=autheHeaders,
            verify=False
        )
        allHosts = []
        if response.status_code <= 299 and response.status_code >= 200:
            # self.objectUUID = response.json()['id']
            for key, value in response.json()['items']:
                allHosts.append([response.json()['items']['name'], [response.json()['items']['id']]])
            print(allHosts)

    def getUUID(self):
        return self.objectUUID

    def getName(self):
        return self.objectPostBody['name']

    def getType(self):
        return self.objectPostBody['type']

    def getGroupMembership(self):
        return self.groupMembership

    def getValue(self):
        return self.objectPostBody['value']

    def getDescription(self):
        return self.objectPostBody['description']