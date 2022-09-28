import csv
import requests
from Model.Providers.FMCConfig import FMC
from Model.Providers.PaloAltoConfig import PaloAlto
from Model.Utilities.LoggingUtils import Logger_GetLogger
from Model.Providers.Provider import buildUrlForResourceWithId


class AccessPolicyObject:

    def __init__(self, ip, domainUUID, policyUUID, domainLocation,
                 accessPolicyLocation, securityZoneObjects, networkObjects,
                 portObjects, filePolicyObjects, urlCategoryObjects,
                 urlObjects, groupObjects, applicationObjects):

        self.url = buildUrlForResourceWithId(ip, domainLocation, domainUUID,
                                             accessPolicyLocation,
                                             policyUUID) + '/accessrules'
        self.securityZones = securityZoneObjects
        self.networks = networkObjects
        self.ports = portObjects
        self.filePolicies = filePolicyObjects
        self.urlCategories = urlCategoryObjects
        self.urls = urlObjects
        self.groups = groupObjects

        self.applications = applicationObjects

    @classmethod
    def FMCAccessPolicyObject(cls, provider: FMC, policyUUID,
                              securityZoneObjects, networkObjects, portObjects,
                              filePolicyObjects, urlCategoryObjects,
                              urlObjects, groupObjects, applicationObjects):

        return cls(provider.fmcIP, provider.domainId, policyUUID,
                   provider.domainLocation, provider.accessPolicyLocation,
                   securityZoneObjects, networkObjects, portObjects,
                   filePolicyObjects, urlCategoryObjects, urlObjects,
                   groupObjects, applicationObjects)

    def __getSecurityZones(self, csvRow):
        for zone in self.securityZones:
            if zone.getName() == csvRow['sourceZones']:
                sourceZone = {}
                sourceZone['type'] = 'SecurityZone'
                sourceZone['name'] = zone.getName()
                sourceZone['id'] = zone.getID()
            elif zone.getName() == csvRow['destinationZones']:
                destinationZone = {}
                destinationZone['type'] = 'SecurityZone'
                destinationZone['name'] = zone.getName()
                destinationZone['id'] = zone.getID()

        return (sourceZone, destinationZone)

    def __getNetworks(self, csvRow):
        sourceNetwork = None
        destinationNetwork = None

        for network in self.networks:
            if network[0] == csvRow['sourceNetworks']:
                sourceNetwork = {}
                sourceNetwork['name'] = network[0]
                # sourceNetwork['id'] = network.getUUID()
                sourceNetwork['id'] = network[1]
                sourceNetwork['type'] = 'Network'
                sourceNetwork['overridable'] = False
                print("Condition 1: ", sourceNetwork)
            elif network[0] == csvRow['destinationNetworks']:
                destinationNetwork = {}
                destinationNetwork['name'] = network[0]
                # destinationNetwork['id'] = network.getUUID()
                destinationNetwork['id'] = network[1]
                destinationNetwork['type'] = 'Network'
                destinationNetwork['overridable'] = False
                print("Condition 2: ", destinationNetwork)

        if sourceNetwork == None or destinationNetwork == None:  #if the network was not found in the list of network objects
            for group in self.groups:
                if group[0] == csvRow['sourceNetworks']:
                    sourceNetwork = {}
                    sourceNetwork['name'] = group[0]
                    sourceNetwork['id'] = group[1]
                    sourceNetwork['type'] = 'NetworkGroup'
                    print("Condition 3: ", sourceNetwork)

                if group[0] == csvRow['destinationNetworks']:
                    destinationNetwork = {}
                    destinationNetwork['name'] = group[0]
                    destinationNetwork['id'] = group[1]
                    destinationNetwork['type'] = 'NetworkGroup'
                    print("Condition 4: ", destinationNetwork)

        return (sourceNetwork, destinationNetwork)

    def __getPorts(self, sourceList, destList, csvRow):
        sourcePortObjectList = []
        destinationPortObjectList = []

        for port in self.ports:
            tempDict = {}

            if port.getName() in sourceList:
                tempDict['overridable'] = False
                tempDict['name'] = port.getName()
                tempDict['id'] = port.getID()
                tempDict['type'] = 'Port'
                sourcePortObjectList.append(tempDict)

            tempDict = {}

            if port.getName() in destList:
                tempDict['overridable'] = False
                tempDict['name'] = port.getName()
                tempDict['id'] = port.getID()
                tempDict['type'] = 'Port'
                destinationPortObjectList.append(tempDict)

        return (sourcePortObjectList, destinationPortObjectList)

    def __getFilePolicies(self, csvRow):
        for fp in self.filePolicies:
            if fp.getName() == csvRow['filePolicy']:
                filePolicy = {}
                filePolicy['name'] = fp.getName()
                filePolicy['id'] = fp.getID()

        return filePolicy

    def __getApplication(self, csvRow):
        application = {}

        for app in self.applications:

            if app.getName() == csvRow['applications']:
                application['name'] = app.getName()
                application['id'] = app.getID()
                application['type'] = "Application"
                application['overridable'] = False
        return application

    def __getUrlCategories(self, csvUrlCategories):

        returnList = []

        for cat in self.urlCategories:
            tempDict = {}
            if cat.getName() in csvUrlCategories:
                tempDict['reputation'] = "ANY_EXCEPT_UNKNOWN"
                tempDict['category'] = {
                    "name": cat.getName(),
                    "id": cat.getID(),
                    'type': 'URLCategory'
                }
                tempDict['type'] = "UrlCategoryAndReputation"

                returnList.append(tempDict)

        return returnList

    def __getUrls(self, csvRow):

        urlDictList = []

        for tempUrl in self.urls:
            if tempUrl[0] == csvRow['urls']:
                urlObject = {}
                urlObject['name'] = tempUrl[0]
                urlObject['id'] = tempUrl[1]
                urlObject['type'] = 'url'

                urlDictList.append(urlObject)

        return urlDictList

    def createPolicy(self, apiToken, csvRow):
        # set authentication in the header
        logger = Logger_GetLogger()
        logger.info("Initiating Policy Creation")

        authHeaders = {"X-auth-access-token": apiToken}

        # Split columns that can contain lists of values
        csvSourcePorts = csvRow['sourcePorts'].split('/')
        csvDestinationPorts = csvRow['destinationPorts'].split('/')
        csvUrlCategories = csvRow['urlCategories'].split('/')

        securityZones = self.__getSecurityZones(csvRow)
        networks = self.__getNetworks(csvRow)
        ports = self.__getPorts(csvSourcePorts, csvDestinationPorts, csvRow)
        filePolicy = self.__getFilePolicies(csvRow)
        urlCategories = self.__getUrlCategories(csvUrlCategories)
        urls = self.__getUrls(csvRow)
        application = self.__getApplication(csvRow)

        logger.info("Got data from CSV files")

        # create body for post request
        postBody = {}
        postBody[
            'action'] = "ALLOW" if "Permit" in csvRow['action'] else "BLOCK"
        postBody['enabled'] = True
        postBody['type'] = 'AccessRule'
        postBody['name'] = csvRow['name']
        postBody['sendEventsToFMC'] = True

        if postBody['action'] == 'ALLOW':
            postBody['filePolicy'] = filePolicy
            postBody[
                'logFiles'] = True if 'TRUE' in csvRow['logFiles'] else False

        postBody['logBegin'] = False if "Permit" in csvRow['action'] else True
        postBody['logEnd'] = not postBody['logBegin']
        postBody['sourceNetworks'] = {'objects': [networks[0]]}
        postBody['sourceZones'] = {"objects": [securityZones[0]]}
        postBody['destinationNetworks'] = {'objects': [networks[1]]}
        postBody['destinationZones'] = {'objects': [securityZones[1]]}
        postBody['sourcePorts'] = {'objects': ports[0]}
        postBody['destinationPorts'] = {'objects': ports[1]}
        postBody['urls'] = {
            "urlCategoriesWithReputation": urlCategories,
            "objects": urls
        }
        postBody['applications'] = {
            "applications": [{
                "deprecated": True,
                "type": "Application",
                "name": application["name"],
                "overridable": application['overridable'],
                "id": application['id'],
            }]
        }

        logger.info("Creation request sent")

        response = requests.post(url=self.url,
                                 headers=authHeaders,
                                 json=postBody,
                                 verify=False)

        if response.status_code <= 299 and response.status_code >= 200:
            self.objectUUID = response.json()['id']
            logger.info("Policy creation successful. {Policy Id:" +
                        self.objectUUID + "}")

        return response.status_code
