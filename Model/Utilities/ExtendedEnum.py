from enum import Enum


class ExtendedEnum(Enum):
    """Provides extended functionality for values from an Enum

    Args:
        Enum (Enum): The Enum type to be extended

    Returns:
        ExtendedEnum: Returns the ExtendedEnum class
    """

    @classmethod
    def list(cls):
        """Provides the set of Enums as a List

        Returns:
            list: The list object created from the inherited Enum class
        """
        return list(map(lambda c: c.value, cls))