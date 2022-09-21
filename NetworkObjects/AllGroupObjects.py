
import requests

class AllGroupObjects:

    def __init__(self, name, id, type):
        self.name = name
        self.id = id
        self.type = type


    def getName(self):
        return self.name

    def getID(self):
        return self.id

    def getType(self):
        return self.type

    # def deleteNetwork(self, apiToken):
    #     id = self.getID()
    #     url = 'https://10.255.5.20/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networks' + id
    #
    #     authHeaders = {"X-auth-access-token": apiToken}
    #
    #     response = requests.get(
    #         url=self.creationURL,
    #         headers=authHeaders,
    #         verify=False
    #     )
    #
    #     return response.status_code



