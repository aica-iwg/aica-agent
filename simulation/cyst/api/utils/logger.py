import logging
import inspect
import json

from pathlib import Path
from typing import Optional, Any, List
from enum import Enum
from collections import OrderedDict, namedtuple
from flags import Flags


FieldInfo = namedtuple("FieldInfo", "text severity")
Caller = namedtuple("Caller", "function line")
Category = Flags("Category", "Message Internal")


class ClassLogSettings:

    def __init__(self, class_name: str) -> None:
        self.class_name = class_name
        self.settings = OrderedDict()
        self.min_severity = 100
        for key in self.settings.keys():
            self.min_severity = min(self.settings[key].severity, self.min_severity)

    def add_setting(self, field_name: str, severity: int = 0, field_text: str = "") -> None:
        if field_text == "":
            field_text = field_name
        self.settings[field_name] = FieldInfo(field_text, severity)
        self.min_severity = min(severity, self.min_severity)


class LogFilteringMode(Enum):
    EXCLUDE_SELECTED = 0,
    INCLUDE_SELECTED = 1

    @classmethod
    def parse(cls, string: str):
        string = string.lower()
        if string in ["0", "exclude", "exclude_selected"]:
            return LogFilteringMode.EXCLUDE_SELECTED
        if string in ["1", "include", "include_selected"]:
            return LogFilteringMode.INCLUDE_SELECTED
        return None


class Log:

    # logging levels from the logging module
    # no need to import logging module everywhere now
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARN = logging.WARN
    WARNING = logging.WARNING  # same as above
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL
    FATAL = logging.FATAL  # same as above
    # logging.DEBUG, WARN... etc. are ints, that's why severity is int everywhere

    # One day, base path and other stuff should be in a top-level conf directory and available for import
    config_file = str(Path(__file__ + "/../../../../conf/logconfig.json").resolve())

    @classmethod
    def set_config_file(cls, path: str) -> None:
        cls.config_file = path

    def add_class_settings(self, settings: ClassLogSettings) -> None:
        self.settings[settings.class_name] = settings

    def add_function_filter(self, function_name: str, severity: int = 0) -> None:
        self.severities[function_name] = severity

    def set_filtering_mode(self, mode: LogFilteringMode) -> None:
        if mode is not None:
            self.mode = mode

    def get_caller_info(self, direct_call: bool = True) -> Caller:
        # stack contains filter(), then log(), then the calling function -> caller is at [2]
        caller_frame = inspect.stack(0)[2 if direct_call else 3]
        caller_locals = caller_frame.frame.f_locals
        caller_function = caller_frame.function
        if 'self' in caller_locals.keys():
            caller_function = caller_locals['self'].__class__.__name__ + "." + caller_function
        elif 'cls' in caller_locals.keys():
            caller_function = caller_locals['cls'].__name__ + "." + caller_function
        return Caller(caller_function, caller_frame.lineno)

    def filter(self, what: Any, severity: int, caller: Caller, category: str = "") -> bool:

        class_name = what.__class__.__name__
        if class_name == "type":
            class_name = what.__name__

        if self.mode == LogFilteringMode.INCLUDE_SELECTED:
            good = False
            for function in self.severities.keys():
                if function == caller.function and self.severities[function] <= severity:
                    good = True
                    break
            if not good:
                return False
        else:
            good = True
            for function in self.severities.keys():
                if function == caller.function and self.severities[function] > severity:
                    return False

        if isinstance(what, str):
            return True

        for key in self.settings.keys():
            if class_name == key and self.settings[key].min_severity <= severity:
                return True
        return False

    def get_log_string(self, what: Any, severity: int, caller: Caller, prefix: bool = True) -> str:

        class_name = what.__class__.__name__
        if class_name == "type":
            class_name = what.__name__

        log_string = ""
        if (prefix):
            log_string = caller.function + ":" + str(caller.line) + " "
        if isinstance(what, str):
            return log_string + what

        log_string += class_name + " {"
        loggged_message = []

        for key in self.settings.keys():
            if class_name == key and self.settings[key].min_severity <= severity:
                class_settings = self.settings[key]
                for field_key in class_settings.settings.keys():
                    field = class_settings.settings[field_key]
                    if severity >= field.severity:
                        attr = getattr(what, field_key)
                        attr_class = attr.__class__.__name__
                        if attr_class == "type":
                            attr_class = attr.__name__
                        if attr_class in self.settings.keys():
                            field_text = self.get_log_string(attr, severity, caller, False)
                        else:
                            field_text = str(attr)
                        loggged_message.append(field.text + " = " + field_text)

        log_string += ", ".join(loggged_message)
        log_string += "}"
        return log_string

    def __call__(self, what: Any, severity: int = logging.INFO, category: Category = Category.no_flags) -> None:
        self.log(what, severity, category, False)

    def log(self, what: Any, severity: int = logging.INFO, category: Category = Category.no_flags, direct_call: bool = True) -> None:
        if severity < self.severity:
            return
        if category & self.excluded_categories and not category & self.included_categories:
            return
        caller = self.get_caller_info(direct_call)
        if self.filter(what, severity, caller):
            self.logger.log(severity, self.get_log_string(what, severity, caller))

    loggers = {}

    @classmethod
    def get_logger(cls, name: str = "default"):
        if name not in cls.loggers.keys():
            cls.loggers[name] = Log(name)
        return cls.loggers[name]

    @classmethod
    def print(cls, what: Any, severity: int = logging.INFO, category: Category = Category.no_flags) -> None:
        cls.get_logger().log(what, severity, category, False)

    def __init__(self, name: str) -> None:
        self.included_categories = Category.no_flags
        self.excluded_categories = Category.no_flags
        self.settings = {}
        self.mode = LogFilteringMode.EXCLUDE_SELECTED
        self.severities = {}
        self.severity = Log.INFO
        self.name = name

        # renaming the python logger to get rid of python loggers' inheritance
        # this makes it possible for a child to not write into a parent's log
        self.logger = logging.getLogger(name.replace(".", "*"))
        self.read_config()

    @classmethod
    def parse_severity(cls, severity: int) -> Optional[int]:
        if isinstance(severity, int):
            return severity
        if not isinstance(severity, str):
            return None
        severity = severity.lower()
        if severity == "debug":
            return logging.DEBUG
        if severity == "info":
            return logging.INFO
        if severity in ["warn", "warning"]:
            return logging.WARN
        if severity == "error":
            return logging.ERROR
        if severity in ["critical", "fatal"]:
            return logging.FATAL
        return None

    classes_configured = False
    class_configs = {}

    def configure_classes(self) -> None:
        if self.classes_configured:
            return

        try:
            with open(self.config_file, 'r') as config:
                config_json = json.load(config)
                for c in config_json["classes"]:
                    class_settings = ClassLogSettings(c["name"])
                    for field in c["fields"]:
                        field_name = field["name"]
                        field_severity = self.parse_severity(field["severity"])
                        field_label = field["name"]
                        if "label" in field.keys():
                            field_label = field["label"]
                        class_settings.add_setting(field_name, field_severity, field_label)
                    self.class_configs[c["label"]] = class_settings
            self.classes_configured = True
        except OSError:
            raise
        except KeyError:
            raise Exception("Invalid config file format (classes/categories section)")

    def list_to_category(self, category_list: List[str]) -> Category:
        result = Category.no_flags
        for cat in category_list:
            if cat.lower() == "internal":
                result |= Category.Internal
            if cat.lower() == "message":
                result |= Category.Message
        return result

    def read_config(self) -> None:
        self.configure_classes()
        logger_names = [self.name]
        for i in range(len(self.name)):
            if (self.name[i] == "."):
                logger_names.append(self.name[:i])

        self.severity = logging.INFO
        output_file = ""
        log_format = "%(levelname)s %(message)s"

        if self.name == "default":
            for c in self.class_configs.keys():
                if self.class_configs[c].class_name not in self.settings.keys():
                    self.add_class_settings(self.class_configs[c])
        else:
            try:
                with open(self.config_file, 'r') as config:
                    config_json = json.load(config)
                    for logger_config in config_json["loggers"]:
                        if logger_config["name"] not in logger_names:
                            continue
                        if "mode" in logger_config.keys():
                            self.set_filtering_mode(LogFilteringMode.parse(logger_config["mode"]))
                        if "severity" in logger_config.keys():
                            self.severity = Log.parse_severity(logger_config["severity"])
                        if "output_file" in logger_config.keys():
                            output_file = str(Path(__file__ + "/../../../../log/" + logger_config["output_file"]).resolve())
                        if "format" in logger_config.keys():
                            log_format = logger_config["format"]
                        if "included_categories" in logger_config.keys():
                            self.included_categories = self.list_to_category(logger_config["included_categories"])
                        if "excluded_categories" in logger_config.keys():
                            self.excluded_categories = self.list_to_category(logger_config["excluded_categories"])
                        if "functions" in logger_config.keys():
                            for function in logger_config["functions"]:
                                self.add_function_filter(function["name"], self.parse_severity(function["severity"]))
                        if "classes" in logger_config.keys():
                            for c in logger_config["classes"]:
                                if c not in self.class_configs.keys():
                                    print("No config with label", c, "found.")
                                else:
                                    self.add_class_settings(self.class_configs[c])
            except OSError:
                raise
            except KeyError:
                raise Exception("Invalid config file format (loggers sections)")

        formatter = logging.Formatter(log_format)
        handler = 0
        if (output_file == ""):
            handler = logging.StreamHandler()
        else:
            handler = logging.FileHandler(output_file)
        handler.setLevel(self.severity)
        self.logger.setLevel(self.severity)
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
