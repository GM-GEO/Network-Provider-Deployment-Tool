import requests
from unicodedata import name

class PortObject:

    objectType = 'port'

    def __init__(self, name, id):

        self.name = name
        self.id = id

    def getName(self):
        return self.name

    def getID(self):
        return self.id
