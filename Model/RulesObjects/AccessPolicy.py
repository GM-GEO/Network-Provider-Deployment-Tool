import csv
import requests
from Model.DataObjects.Enums.ObjectTypeEnum import ObjectTypeEnum
from Model.Providers.FMCConfig import FMC
from Model.Providers.PaloAltoConfig import PaloAlto
from Model.Utilities.LoggingUtils import Logger_GetLogger
from Model.Providers.Provider import buildUrlForResourceWithId, buildUrlForResource


class AccessPolicyObject:

    def __init__(self, ip, domainUUID, policyUUID, domainLocation,
                 accessPolicyLocation, securityZoneObjects, networkObjects,
                 portObjects, filePolicyObjects, urlCategoryObjects,
                 urlObjects, groupObjects, applicationObjects, urls):

        self.url = buildUrlForResourceWithId(ip, domainLocation, domainUUID,
                                             accessPolicyLocation,
                                             policyUUID) + '/accessrules'
        self.autoNATruleURL = buildUrlForResourceWithId(ip, domainLocation, domainUUID,
                                             accessPolicyLocation,
                                             policyUUID) + '/autonatrules'
        self.securityRuleP = buildUrlForResource(ip, domainLocation, '', accessPolicyLocation)


        self.urlTest = urls
        print("All URLs required: ", self.urlTest)


        print("NAT auto rule url: ", self.autoNATruleURL)
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

        accessRuleURL = buildUrlForResourceWithId(provider.fmcIP, provider.domainLocation, provider.domainId, provider.accessPolicyLocation, "005056B6-DCA2-0ed3-0000-017179871248") + '/accessrules'
        autoNATRuleUrl = buildUrlForResourceWithId(provider.fmcIP, provider.domainLocation, provider.domainId, provider.natPolicyLocation, '005056B6-DCA2-0ed3-0000-004294974477') + '/autonatrules'
        manualNATRuleUrl = buildUrlForResourceWithId(provider.fmcIP, provider.domainLocation, provider.domainId, provider.natPolicyLocation, '005056B6-DCA2-0ed3-0000-004294974477') + '/manualnatrules'

        urls = [accessRuleURL, autoNATRuleUrl, manualNATRuleUrl]

        return cls(provider.fmcIP, provider.domainId, policyUUID,
                   provider.domainLocation, provider.accessPolicyLocation,
                   securityZoneObjects, networkObjects, portObjects,
                   filePolicyObjects, urlCategoryObjects, urlObjects,
                   groupObjects, applicationObjects, urls)
    @classmethod
    def PaloAltoAccessPolicyObject(cls, provider: PaloAlto, policyUUID,
                              securityZoneObjects, networkObjects, portObjects,
                              filePolicyObjects, urlCategoryObjects,
                              urlObjects, groupObjects, applicationObjects):

        securityRuleUrl = buildUrlForResource(provider.paloAltoIP, provider.domainLocation, '', provider.securityRuleLocation)
        natRuleUrl = buildUrlForResource(provider.paloAltoIP, provider.domainLocation, '', provider.natRuleLocation)

        urls = [securityRuleUrl, natRuleUrl]
        return cls(provider.paloAltoIP, '', '',
                   provider.domainLocation, "",
                   securityZoneObjects, networkObjects, portObjects,
                   filePolicyObjects, urlCategoryObjects, urlObjects,
                   groupObjects, applicationObjects, urls)

    def __getSecurityZones(self, csvRow):
        sourceZone = {}
        destinationZone = {}
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

    def __getPSecurityZones(self, csvRow):
        sourceZone = []
        destinationZone = []
        for zone in self.securityZones:
            if zone[0] == csvRow['sourceZones']:
                # sourceZone = []
                sourceZone.append(zone[0])
            elif zone[0] == csvRow['destinationZones']:
                # destinationZone = []
                destinationZone.append(zone[0])

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
                sourceNetwork[
                    'type'] = ObjectTypeEnum.NETWORK.value.capitalize()
                sourceNetwork['overridable'] = False
                print("Condition 1: ", sourceNetwork)
            elif network[0] == csvRow['destinationNetworks']:
                destinationNetwork = {}
                destinationNetwork['name'] = network[0]
                # destinationNetwork['id'] = network.getUUID()
                destinationNetwork['id'] = network[1]
                destinationNetwork[
                    'type'] = ObjectTypeEnum.NETWORK.value.capitalize()
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

    def __getPNetworks(self, csvRow):
        sourceNetwork = None
        destinationNetwork = None

        for network in self.networks:
            if network[0] == csvRow['sourceNetworks']:
                sourceNetwork = []
                sourceNetwork.append(network[0])
                print("Condition 1: ", sourceNetwork)
            elif network[0] == csvRow['destinationNetworks']:
                destinationNetwork = []
                destinationNetwork.append(network[0])
                print("Condition 2: ", destinationNetwork)

        if sourceNetwork == None or destinationNetwork == None:  # if the network was not found in the list of network objects
            for group in self.groups:
                if group[0] == csvRow['sourceNetworks']:
                    sourceNetwork = []
                    sourceNetwork.append(group[0])
                    print("Condition 3: ", sourceNetwork)

                if group[0] == csvRow['destinationNetworks']:
                    destinationNetwork = []
                    destinationNetwork.append(group[0])
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

    def __getPPorts(self, sourceList, destList, csvRow):
        sourcePortObjectList = []
        destinationPortObjectList = []

        for port in self.ports:

            if port[0] in sourceList:
                sourcePortObjectList.append(port[0])


            if port[0] in destList:
                destinationPortObjectList.append(port[0])

        return (sourcePortObjectList, destinationPortObjectList)

    def __getFilePolicies(self, csvRow):
        filePolicy = {}

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

    def __getPApplication(self, csvRow):
        application = []

        for app in self.applications:

            if app[0] == csvRow['applications']:
                application.append(app[0])
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

    def __getPUrls(self, csvRow):

        urlDictList = []

        for tempUrl in self.urls:
            if tempUrl[0] == csvRow['urls']:

                urlDictList.append(tempUrl[0])

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
        postBody['action'] = "ALLOW" if "Permit" in csvRow['action'] else "BLOCK"
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
        # postBody['applications'] = {
        #     "applications": [{
        #         "deprecated": True,
        #         "type": "Application",
        #         "name": application["name"],
        #         "overridable": application['overridable'],
        #         "id": application['id'],
        #     }]
        # }

        logger.info("Creation request sent")
        print("Rule creation postBody: ", postBody)

        response = requests.post(url=self.urlTest[0],
                                 headers=authHeaders,
                                 json=postBody,
                                 verify=False)

        if response.status_code <= 299 and response.status_code >= 200:
            self.objectUUID = response.json()['id']
            logger.info("Policy creation successful. {Policy Id:" +
                        self.objectUUID + "}")

        print("Response rule creation: ", response.json())

        return response.status_code

    def createNATRules(self, apiToken, csvRow):
        logger = Logger_GetLogger()
        logger.info("Initiating Policy Creation")

        authHeaders = {"X-auth-access-token": apiToken}

        securityZones = self.__getSecurityZones(csvRow)
        networks = self.__getNetworks(csvRow)
        filePolicy = self.__getFilePolicies(csvRow)
        urls = self.__getUrls(csvRow)
        application = self.__getApplication(csvRow)

        postBody = {}

        postBody['originalNetwork'] = networks[0]
        # postBody['sourceZones'] = {"objects": [securityZones[0]]}
        # if networks[1] != None:
        postBody['translatedNetwork'] = networks[1]
        # postBody['destinationZones'] = {'objects': [securityZones[1]]}
        postBody['type'] = 'FTDAutoNatRule'
        postBody['natType'] = 'STATIC'
        postBody['interfaceIpv6'] = False
        postBody['fallThrough'] = False
        postBody['dns'] = False
        postBody['routeLookup'] = False
        postBody['noProxyArp'] = False
        postBody['netToNet'] = False
        postBody['sourceInterface'] = securityZones[0]
        postBody['destinationInterface'] = securityZones[1]
        # "type": "FTDAutoNatRule",
        # "natType": "STATIC",
        # "interfaceIpv6": false,
        # "fallThrough": false,
        # "dns": false,
        # "routeLookup": false,
        # "noProxyArp": false,
        # "netToNet": false,
        url = 'https://10.255.20.10/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/ftdnatpolicies/005056B6-DCA2-0ed3-0000-004294974477/autonatrules'

        print("NAT postBody: ", postBody)

        response = requests.post(url=self.urlTest[1],
                                 headers=authHeaders,
                                 json=postBody,
                                 verify=False)

        print("NAT response: ", response.json())

    def createManualNATrule(self, apiToken, csvRow):

        logger = Logger_GetLogger()
        logger.info("Initiating Policy Creation")

        authHeaders = {"X-auth-access-token": apiToken}

        csvSourcePorts = csvRow['sourcePorts'].split('/')
        csvDestinationPorts = csvRow['destinationPorts'].split('/')

        securityZones = self.__getSecurityZones(csvRow)
        networks = self.__getNetworks(csvRow)
        filePolicy = self.__getFilePolicies(csvRow)
        urls = self.__getUrls(csvRow)
        application = self.__getApplication(csvRow)
        ports = self.__getPorts(csvSourcePorts, csvDestinationPorts, csvRow)
        # ports[0][0]['type'] = 'ProtocolPortObject'
        for i in ports[0]:
            i['type'] = 'ProtocolPortObject'
        for i in ports[1]:
            i['type'] = 'ProtocolPortObject'

        postBody = {}
        if ports[1] != []:
            print("Empty port: ", ports[1])
            postBody["originalDestinationPort"] = ports[1][0]
        postBody['originalSource'] = networks[0]

        if ports[0] != []:
            print("Empty port: ", ports[1])
            postBody['originalSourcePort'] = ports[0][0]

        postBody['translatedDestination'] = networks[1]
        postBody['translatedSource'] = networks[1]
        postBody['originalDestination'] = networks[0]

        postBody['sourceInterface'] = securityZones[0]
        postBody['destinationInterface'] = securityZones[1]


        if ports[1] != []:
            postBody['translatedDestinationPort'] = ports[1][0]

        if ports[0] != []:
            postBody['translatedSourcePort'] = ports[0][0]

        postBody['unidirectional'] = False
        postBody['interfaceInOriginalDestination'] = False
        postBody['type'] = 'FTDManualNatRule'
        postBody['enabled'] = True
        postBody['natType'] = 'STATIC'
        postBody['interfaceIpv6'] = False
        postBody['fallThrough'] = False
        postBody['dns'] = False
        postBody['routeLookup'] = False
        postBody['noProxyArp'] = False
        postBody['netToNet'] = False

        url = 'https://10.255.20.10/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/ftdnatpolicies/005056B6-DCA2-0ed3-0000-004294974477/manualnatrules'

        print("Manual NAT postBody: ", postBody)

        response = requests.post(url=self.urlTest[2],
                                 headers=authHeaders,
                                 json=postBody,
                                 verify=False)

        print("NAT response: ", response.json())
        print('Status code: ', response.status_code)


    def createPRules(self, authHeader, csvRow):
        logger = Logger_GetLogger()
        logger.info("Initiating Policy Creation in Palo Alto")


        # Split columns that can contain lists of values
        csvSourcePorts = csvRow['sourcePorts'].split('/')
        csvDestinationPorts = csvRow['destinationPorts'].split('/')
        csvUrlCategories = csvRow['urlCategories'].split('/')

        securityZones = self.__getPSecurityZones(csvRow)
        networks = self.__getPNetworks(csvRow)
        ports = self.__getPPorts(csvSourcePorts, csvDestinationPorts, csvRow)
        filePolicy = self.__getFilePolicies(csvRow)
        urlCategories = self.__getUrlCategories(csvUrlCategories)
        urls = self.__getPUrls(csvRow)
        application = self.__getPApplication(csvRow)

        logger.info("Got data from CSV files")

        # create body for post request
        postBody = {}
        postBody['entry'] = {}
        postBody['entry']['@name'] = csvRow['name']
        postBody['entry']['@location'] = 'vsys'
        postBody['entry']['@vsys'] = 'vsys1'
        postBody['entry']['from'] = {"member": securityZones[0]}
        postBody['entry']['to'] = {"member": securityZones[1]}
        postBody['entry']['source'] = {"member": networks[0]}
        postBody['entry']['destination'] = {"member": networks[1]}
        postBody['entry']['service'] = {"member": ports[0]}
        postBody['entry']['category'] = {"member": urls}
        postBody['entry']['application'] = {"member": ["any"]}
        postBody['entry']['negate-source'] = "no"
        postBody["entry"]["negate-destination"] = "no"
        postBody["entry"]["disabled"] = "no"
        postBody["entry"]["action"] = "allow"
        postBody["entry"]["icmp-unreachable"] = "no"
        postBody["entry"]["disable-inspect"] = "no"
        postBody["entry"]["rule-type"] = "universal"
        postBody["entry"]["option"] = {"disable-server-response-inspection": "no"}
        postBody["entry"]["log-start"] = "no"
        postBody["entry"]["log-end"] = "yes"

        print("Palo Alto postBody: ", postBody)
        logger.info("Creation request sent")

        params = {
            "location": "vsys",
            "vsys": "vsys1",
            "name": csvRow['name']
        }

        url = 'https://10.255.20.11/restapi/v10.2/Policies/SecurityRules'

        response = requests.post(url=self.urlTest[0],
                                 params=params,
                                 headers=authHeader,
                                 json=postBody,
                                 verify=False)

        print(response.json())

        return response.status_code

    def createPNATRules(self, authHeader, csvRow):
        logger = Logger_GetLogger()
        logger.info("Initiating Policy Creation in Palo Alto")


        # Split columns that can contain lists of values
        csvSourcePorts = csvRow['sourcePorts'].split('/')
        csvDestinationPorts = csvRow['destinationPorts'].split('/')
        csvUrlCategories = csvRow['urlCategories'].split('/')

        securityZones = self.__getPSecurityZones(csvRow)
        networks = self.__getPNetworks(csvRow)
        ports = self.__getPPorts(csvSourcePorts, csvDestinationPorts, csvRow)
        filePolicy = self.__getFilePolicies(csvRow)
        urlCategories = self.__getUrlCategories(csvUrlCategories)
        urls = self.__getUrls(csvRow)
        application = self.__getPApplication(csvRow)

        logger.info("Got data from CSV files")

        # create body for post request
        postBody = {}
        postBody['entry'] = {}
        postBody['entry']['@name'] = csvRow['name']
        postBody['entry']['@location'] = 'vsys'
        postBody['entry']['@vsys'] = 'vsys1'
        postBody['entry']['from'] = {"member": securityZones[0]}
        postBody['entry']['to'] = {"member": securityZones[1]}
        postBody['entry']['source'] = {"member": networks[0]}
        postBody['entry']['destination'] = {"member": networks[1]}
        postBody['entry']['service'] = ports[0]
        postBody['entry']['active-active-device-binding'] = "primary"
        postBody["entry"]["disabled"] = "no"

        print("Palo Alto postBody: ", postBody)
        logger.info("Creation request sent")

        params = {
            "location": "vsys",
            "vsys": "vsys1",
            "name": csvRow['name']
        }

        url = 'https://10.255.20.11/restapi/v10.2/Policies/NatRules'

        response = requests.post(url=self.urlTest[1],
                                 params=params,
                                 headers=authHeader,
                                 json=postBody,
                                 verify=False)

        print("Palo Alto NAT response: ", response.json())

        return response.status_code







