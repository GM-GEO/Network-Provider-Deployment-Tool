import logging

def Create_Logger(logPath, fileName):

    qualifiedFileName = "{0}/{1}.log".format(logPath, fileName)

    logFormatter = logging.Formatter("%(asctime)s  [%(levelname)-5.5s]  %(message)s")
    rootLogger = logging.getLogger()
    rootLogger.setLevel(logging.DEBUG)

    fileHandler = logging.FileHandler(qualifiedFileName)
    fileHandler.setFormatter(logFormatter)
    rootLogger.addHandler(fileHandler)

    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(logFormatter)
    rootLogger.addHandler(consoleHandler)

    return rootLogger

def Logger_AddBreakLine():
    rootLogger = logging.getLogger()
    rootLogger.info("*****************************************************")