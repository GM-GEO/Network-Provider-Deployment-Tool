import os

from Providers import FMC
from datetime import datetime
from Utilities.FileUtils import checkValidFileExtension
from Utilities.FileUtils import readCSVFromFile
from Utilities.LoggingUtils import *


def main():

    desktop = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')
    log = Create_Logger(
        desktop, "%s %s" % ("Network Profile Tool Log - ",
                            datetime.now().strftime("%b-%d-%Y-%H-%M-%S")))
    objectFile = ''
    ruleFile = ''
    connectionIP = ''

    while not checkValidFileExtension(objectFile):
        log.info("Select the Object file (supported extensions: .csv): ")
        objectFile = str(input())

    log.info("Object file selected. {Filename: " + objectFile + "}")

    while not checkValidFileExtension(ruleFile):
        log.info("Select the Rules file (supported extensions: .csv): ")
        ruleFile = str(input())

    log.info("Rule file selected. {Filename: " + ruleFile + "}")

    log.info("Enter FMC IP Address:")
    connectionIP = str(input())

    labFMC = FMC(connectionIP)
    #
    parsedObjectCSV = readCSVFromFile(objectFile)
    parsedRuleCSV = readCSVFromFile(ruleFile)
    #
    #
    for index, object in parsedObjectCSV.items():
        labFMC.addObject('e276abec-e0f2-11e3-8169-6d9ed49b625f',
                         object['type'],
                         object['name'],
                         object['value'],
                         group=object['group'])

    Logger_AddBreakLine()

    # print("Get Object List: ", labFMC.getObjectList('host'))
    #
    # print("Apply result: ", labFMC.applyObjectList("host"))
    # print("Creating group: ", labFMC.createGroups('host'))

    log.info("Get Object List: ", labFMC.getObjectList('network'))

    log.info("Apply result: ", labFMC.applyObjectList("network"))
    log.info("Creating group: ", labFMC.createGroups('network'))

    log.info("Get Object List: ", labFMC.getObjectList('url'))

    log.info("Apply result: ", labFMC.applyObjectList("url"))
    log.info("Creating group: ", labFMC.createGroups('url'))

    # print("Get Object List: ", labFMC.getObjectList('fqdn'))
    #
    # print("Apply result: ", labFMC.applyObjectList("fqdn"))
    # print("Creating group: ", labFMC.createGroups('fqdn'))
    #
    # print("Ports: ", labFMC.getObjectList('port'))
    # print("Networks: ", labFMC.getObjectList('network'))

    # n = labFMC.getObjectList('network')
    # print("N: ", n[-1].getName(), " ", n[-1].getID())

    # print(labFMC.geturlCat())

    #
    for index, rule in parsedRuleCSV.items():
        result = labFMC.createAccessRule(rule)
        log.info("Rule creation: ", result)

    #


if __name__ == '__main__':
    main()