import unittest
from pathlib import Path
from cyst.api.utils.logger import Log, Category


class LogTest1:

    @classmethod
    def test(cls):
        cls.log = Log.get_logger("parent")

        cls.randomInfo = 5
        cls.foo = "bar"
        cls.log(cls, Log.WARN, Category.Internal)  # will be ignored, wrong category
        cls.log.log(cls, Log.ERROR, Category.Internal | Category.Message)


class Tool:

    def __init__(self, name):
        self.name = name


class Color:

    def __init__(self, name):
        self.name = name


class LogTest2:

    def __init__(self):
        self.log = Log.get_logger("parent.child")

        self.tool = Tool("Hammer")
        self.color = Color("Red")

        self.log.log(self, Log.DEBUG)  # will be ignored, low level
        self.log(self, Log.WARN)


def e():
    exclude = Log.get_logger("exclude")
    exclude.log("excluded")


class TestPolicy(unittest.TestCase):

    def test_logger(self):
        base_path = Path(__file__ + "/../../../").resolve()
        Log.set_config_file(str(base_path) + "/tests/unit/logconfig.json")
        LogTest1.test()
        LogTest2()
        Log.print("default logger")
        Log.print(Tool("Screwdriver"), Log.WARN)

        simple = Log.get_logger("simple")
        simple.log(Color("Octarine"))

        e()
        exclude = Log.get_logger("exclude")
        exclude.log(Tool(""))


if __name__ == '__main__':
    unittest.main()
