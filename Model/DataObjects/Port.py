import requests
from unicodedata import name

class PortObject:

    objectType = 'port'

    def __init__(self, name, id):
        """
        The Port object with the name and id.
        :param name: The name of the Port object.
        :param id: The id of the Port object.
        """

        self.name = name
        self.id = id

    def getName(self):
        """

        :return: Port name
        """
        return self.name

    def getID(self):
        """

        :return: Port id
        """
        return self.id
