import os

from datetime import datetime
from Model.Providers.FMCConfig.FMC import FMC
from Model.Utilities.FileUtils import *
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

    if serviceProvider == ProviderEnum.PALOALTO.value:
        pass
    elif serviceProvider == ProviderEnum.FMC.value:
        while not checkValidIPAddress(ipAddress):
            log.info("Enter FMC IP Address: ")
            ipAddress = str(input())

        labFMC = FMC(ipAddress)

        parsedObjectCSV = readCSVFromFile(objectFile)
        parsedRuleCSV = readCSVFromFile(ruleFile)

        Logger_AddBreakLine()

        for index, object in parsedObjectCSV.items():
            labFMC.addObject(labFMC.domainId,
                             object['type'],
                             object['name'],
                             object['value'],
                             group=object['group'])

        log.info("Get Object List: ", labFMC.getObjectList("network"))
        log.info("Apply result: ", labFMC.applyObjectList("network"))
        log.info("Creating group: ", labFMC.createGroups("network"))
        log.info("Get Object List: ", labFMC.getObjectList("url"))
        log.info("Apply result: ", labFMC.applyObjectList("url"))
        log.info("Creating group: ", labFMC.createGroups("url"))

        Logger_AddBreakLine()

        for index, rule in parsedRuleCSV.items():
            result = labFMC.createAccessRule(rule)
            log.info("Rule creation: ", result)

        pass


if __name__ == '__main__':
    main()