from collections import OrderedDict
import logging


def checkValidFileExtension(filename):
    validFileType = False
    log = logging.getLogger()

    if filename:
        if filename.lower().endswith(".csv"):
            validFileType = True
        else:
            log.info("Invalid file type selected")
    else:
        validFileType = False

    return validFileType


def readCSVFromFile(csvFilePath):
    # Create a dictionary
    data = OrderedDict()

    with open(csvFilePath, encoding='utf-8') as csvf:
        csvReader = csv.DictReader(csvf)

        currentRuleNumber = 0

        for rows in csvReader:

            rows.pop('', None)
            data[currentRuleNumber] = rows
            currentRuleNumber += 1

    return data