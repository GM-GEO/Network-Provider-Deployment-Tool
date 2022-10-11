import os

from getpass import getpass
from datetime import datetime
from Model.Providers.FMCConfig.FMC import FMC
from Model.Providers.PaloAltoConfig.PaloAlto import PaloAlto
from Model.Utilities.FileUtils import *
from Model.Utilities.StringUtils import *
from Model.Utilities.LoggingUtils import *
from Model.Utilities.IPUtils import *
from Model.Providers.Provider import *


def main():
    """ The main head of the program. The user will select their provider, enter the relevant credentials,
        select the files for objects and rules, and have them be automatically created
    """
    desktop = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')
    log = Create_Logger(
        desktop, "%s %s" % ("Network Profile Tool Log - ",
                            datetime.now().strftime("%b-%d-%Y-%H-%M-%S")))
    objectFile = ''
    ruleFile = ''
    serviceProvider = ''
    ipAddress = ''
    username = None
    password = None

    while not checkServiceProvider(serviceProvider):
        log.info("Select a Network Provider: ")
        log.info(ProviderEnum.list())
        serviceProvider = str(input())

    while not checkValidFileExtension(objectFile):
        log.info("Select the Object file (supported extensions: .csv): ")
        objectFile = str(input())

    log.info("Object file selected. {Filename: " + objectFile + "}")

    while not checkValidFileExtension(ruleFile):
        log.info("Select the Rules file (supported extensions: .csv): ")
        ruleFile = str(input())

    log.info("Rule file selected. {Filename: " + ruleFile + "}")
    parsedObjectCSV = readCSVFromFile(objectFile)
    parsedRuleCSV = readCSVFromFile(ruleFile)

    if serviceProvider == ProviderEnum.PALOALTO.value:
        while not checkValidIPAddress(ipAddress):
            log.info("Enter Palo Alto IP Address: ")
            ipAddress = str(input())

        paloAlto = PaloAlto(ipAddress)

        for index, object in parsedObjectCSV.items():
            paloAlto.addObject('',
                               object['type'],
                               object['name'],
                               object['value'],
                               group=object['group'])

        print("Object list Network: ", paloAlto.getObjectList('network'))
        print("Object list FQDN: ", paloAlto.getObjectList('fqdn'))
        print("Object list Url: ", paloAlto.getObjectList('host'))
        paloAlto.applyObjectList('host')
        print("FQDNs: ", paloAlto.getObjectList('fqdn'))
        paloAlto.applyObjectList('fqdn')
        print("Url groups: ", paloAlto.createGroupMembershipLists('url'))

        for index, rule in parsedRuleCSV.items():
            paloAlto.createAccessRule(rule)

        for index, rule in parsedRuleCSV.items():
            paloAlto.createNATRule(rule)



        Logger_AddBreakLine()

    elif serviceProvider == ProviderEnum.FMC.value:
        while not checkValidIPAddress(ipAddress):
            log.info("Enter FMC IP Address: ")
            ipAddress = str(input())

        while not checkValidUsername(username):
            log.info("Enter Username:")
            username = str(input())

        while not checkValidPassword(password):
            log.info("Enter password:")
            password = str(input())

        labFMC = FMC(ipAddress, username, password)

        log.info("Parsing CSV Files.")

        parsedObjectCSV = readCSVFromFile(objectFile)
        parsedRuleCSV = readCSVFromFile(ruleFile)

        log.info("CSV files read.")

        Logger_AddBreakLine()

        for index, object in parsedObjectCSV.items():
            labFMC.addObject('', object['type'],
                             object['name'],
                             object['value'],
                             group=object['group'])

        labFMC.getObjectList("host")
        log.info("retrieved Host list.")

        labFMC.applyObjectList("host")
        log.info("applied changes to Hosts.")

        labFMC.createGroups("host")
        log.info("created Host Groups.")

        labFMC.getObjectList("network")
        log.info("retrieved Network list.")

        labFMC.applyObjectList("network")
        log.info("applied Network results.")

        labFMC.createGroups("network")
        log.info("created Network group.")

        labFMC.getObjectList("url")
        log.info("retrieved URL list.")

        labFMC.applyObjectList("url")
        log.info("applied URL results.")

        labFMC.createGroups("url")
        log.info("created group.")

        for index, rule in parsedRuleCSV.items():
            labFMC.createAccessRule(rule)

        for index, rule in parsedRuleCSV.items():
            labFMC.createNATRules(rule)

        for index, rule in parsedRuleCSV.items():
            labFMC.createManualNATrule(rule)

        Logger_AddBreakLine()

    pass


if __name__ == '__main__':
    main()