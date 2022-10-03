from Model.DataObjects.Enums.YesNoEnum import YesNoEnum
from Model.DataObjects.Enums.GroupTypeEnum import GroupTypeEnum


def checkValidUsername(userName: str):

    ValidUserName = False
    if userName:
        ValidUserName = True

    return ValidUserName


def checkValidPassword(password: str):

    ValidPassword = False
    if password:
        ValidPassword = True

    return ValidPassword


def checkYesNoResponse(response: str):
    validResponse = False

    if response and response in YesNoEnum.list():
        validResponse = True
    else:
        validResponse = False

    return validResponse


def checkValidGroupType(type: str):
    validResponse = False

    if type and type in GroupTypeEnum.list():
        validResponse = True
    else:
        validResponse = False

    return validResponse