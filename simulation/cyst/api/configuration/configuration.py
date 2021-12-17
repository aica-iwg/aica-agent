# The definition here is only to make the type of configuration items obvious.
# Because we are operating on dataclasses, the initialization order precludes us from having some default initialized
# value, which is a real shame (though understandable)
import dataclasses
import uuid
from typing import Any



class ConfigItem:
    id: str

"""
A utility class to recursively copy ConfigItems due to the destructive property of environment creation.
At the moment we use deepcopy tho, and this is a backup option.
"""
class ConfigItemCloner:

    @classmethod
    def clone(cls, item: Any):
        """ Recursive semi-deepcopy for dataclasses containing only list type collections.
         Non list and non ConfigItem objects are only shallow copied """
        if isinstance(item, list):
            return [cls.clone(value) for value in item]
        if not isinstance(item, ConfigItem):
            return item
        if not dataclasses.is_dataclass(item):
            raise RuntimeError("ConfigItem is not a dataclass")

        return dataclasses.replace(item,
                                   **dict(
                                       map(lambda field: cls._clone_field(item, field),
                                           filter(lambda field: cls._needs_further_processing(item, field),
                                                  dataclasses.fields(item)
                                                  )
                                           )
                                   )
                                   )

    @classmethod
    def _needs_further_processing(cls, item: ConfigItem, field: dataclasses.Field):
        return isinstance(getattr(item, field.name), ConfigItem) or \
               isinstance(getattr(item, field.name), list) # be careful with other collections, right now we dont use any,
                                                            # but future changes might be problematic as IPAddress,
                                                            # IPNetwork, str are all collections.abc.Collections,

    @classmethod
    def _clone_field(cls, item: ConfigItem, field: dataclasses.Field):
        value = getattr(item, field.name)
        if isinstance(value, list):
            return field.name, [cls.clone(obj) for obj in value]
        return field.name, cls.clone(value)




    @classmethod
    def _duplicate_field(cls, item: ConfigItem, field: dataclasses.Field):
        value = getattr(item, field.name)
        if isinstance(value, list):
            return field.name, [cls.duplicate(obj) for obj in value]
        return field.name, cls.duplicate(value)


    @classmethod
    def duplicate(cls, item: Any):
        """
        Makes semi-deep copies of dataclasses, but recursively dives into all ConfigItems. For any ConfigItem,
         changes the id field. Non ConfigItem fields are shallow copied.
         Useful when we need to use the same ConfigItem multiple times but change the id, as the environment
          configuration does not allow id duplication.
        """
        if isinstance(item, list):
            return [cls.duplicate(value) for value in item]
        if not isinstance(item, ConfigItem):
            return item
        if not dataclasses.is_dataclass(item):
            raise RuntimeError("ConfigItem is not a dataclass")

        return dataclasses.replace(item,
                                   **dict(
                                       map(lambda field: cls._duplicate_field(item, field),
                                           filter(lambda field: cls._needs_further_processing(item, field),
                                                  dataclasses.fields(item)
                                                  )
                                           )
                                   ),
                                   id=uuid.uuid4()
                                   )
