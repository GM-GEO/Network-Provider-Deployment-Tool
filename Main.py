import os

from datetime import datetime
from Model.Providers.FMCConfig.FMC import FMC
from Model.Utilities.FileUtils import *
from Model.Utilities.LoggingUtils import *
from Model.Providers.Provider import *


def main():

    desktop = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')
    log = Create_Logger(
        desktop, "%s %s" % ("Network Profile Tool Log - ",
                            datetime.now().strftime("%b-%d-%Y-%H-%M-%S")))
    objectFile = ''
    ruleFile = ''
    connectionIP = ''
    serviceProvider = ''

    while not checkServiceProvider(serviceProvider):
        log.info("Select a Network Provider: ")
        log.info(ServiceProvider.list())
        serviceProvider = str(input())

    while not checkValidFileExtension(objectFile):
        log.info("Select the Object file (supported extensions: .csv): ")
        objectFile = str(input())

    log.info("Object file selected. {Filename: " + objectFile + "}")

    while not checkValidFileExtension(ruleFile):
        log.info("Select the Rules file (supported extensions: .csv): ")
        ruleFile = str(input())

    log.info("Rule file selected. {Filename: " + ruleFile + "}")

    if serviceProvider == ServiceProvider.PALOALTO.value:
        pass
    elif serviceProvider == ServiceProvider.FMC.value:
        log.info("Enter FMC IP Address:")
        connectionIP = str(input())
        labFMC = FMC(connectionIP)

        parsedObjectCSV = readCSVFromFile(objectFile)
        parsedRuleCSV = readCSVFromFile(ruleFile)

        Logger_AddBreakLine()

        for index, object in parsedObjectCSV.items():
            labFMC.addObject('e276abec-e0f2-11e3-8169-6d9ed49b625f',
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