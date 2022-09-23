from unicodedata import name
import requests


class ServiceObject:

    def __init__(self, name, id):
        self.name = name
        self.id = id

    def getName(self):
        return self.name

    def getID(self):
        return self.id
