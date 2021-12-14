from typing import TextIO, Callable


def serialize_toml(file: TextIO, *args):
    from tools.serde_customized.toml import to_toml
    _serialize(file, to_toml, *args)


def serialize_json(file: TextIO, *args):
    from tools.serde_customized.json import to_json
    _serialize(file, to_json, *args)


def serialize_yaml(file: TextIO, *args):
    from tools.serde_customized.yaml import to_yaml
    _serialize(file, to_yaml, *args)


def serialize_gura(file: TextIO, *args):
    from tools.serde_customized.gura import to_gura
    _serialize(file, to_gura, *args)


def _serialize(file: TextIO, func: Callable, *args):

    config_items = {}
    for i in range(0, len(args)):
        config_items[f"ConfigItem{i}"] = args[i]

    file.write(func(config_items))
