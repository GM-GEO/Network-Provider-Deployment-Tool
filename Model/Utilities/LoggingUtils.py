import logging
import urllib3


def Create_Logger(logPath: str, fileName: str):
    """Creates a logger that both exports to the file specified in the fileName
        and shows logged messages in the CMD terminal

    Args:
        logPath (str): The path to where the log file will be created
        fileName (str): The name of the logFile to be created

    Returns:
        Logger: Returns the configured Logger object
    """

    qualifiedFileName = "{0}/{1}.log".format(logPath, fileName)

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    logFormatter = logging.Formatter(
        "%(asctime)s  [%(levelname)-5.5s]  %(message)s")
    rootLogger = logging.getLogger()
    rootLogger.setLevel(logging.INFO)

    fileHandler = logging.FileHandler(qualifiedFileName)
    fileHandler.setFormatter(logFormatter)
    rootLogger.addHandler(fileHandler)

    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(logFormatter)
    rootLogger.addHandler(consoleHandler)

    return rootLogger


def Logger_AddBreakLine():
    """Creates a string of asterisks to serve as a ling break in the log file
    """
    rootLogger = logging.getLogger()
    rootLogger.info("*****************************************************")


def Logger_GetLogger():
    """Retrieves the current Logger object

    Returns:
        Logger: Returns the current Logger object
    """
    return logging.getLogger()