import unittest
import random

from cyst.api.environment.environment import Environment


class ActionTests(unittest.TestCase):

    def test_0000_parameter_domains(self) -> None:
        env = Environment.create()

        # Domain 'ANY' means that the value can be arbitrary, therefore you can't get reasonable values from it
        domain_any = env.configuration.action.create_action_parameter_domain_any()

        self.assertTrue(domain_any.validate(3), "Number 3 is in ANY domain")
        self.assertTrue(domain_any.validate("hello"), "String 'hello' is in ANY domain")

        with self.assertRaises(ValueError):
            len(domain_any)

        with self.assertRaises(IndexError):
            x = random.choice(domain_any)

        with self.assertRaises(IndexError):
            x = domain_any[0]

        # Range domain represents integer sequence
        domain_range = env.configuration.action.create_action_parameter_domain_range(1, 1, 10, 2)

        self.assertFalse(domain_range.validate(0), "Outside lower bound")
        self.assertFalse(domain_range.validate(11), "Outside upper bound")
        self.assertFalse(domain_range.validate(2), "Wrong step")
        self.assertEqual(len(domain_range), 4, "Correct number of elements")
        self.assertEqual(domain_range[4], 9, "Correct element selection")
        self.assertTrue(domain_range.validate(random.choice(domain_range)), "Everything works")

        # Options represent an enumeration of values
        domain_options = env.configuration.action.create_action_parameter_domain_options(3, ["hello", 3, 7, "world"])

        self.assertTrue(domain_options.validate("world"), "Works for what is in")
        self.assertFalse(domain_options.validate("Hello"), "Does not work for what is not in")
        self.assertEqual(len(domain_options), 4, "Correct number of elements")
        self.assertEqual(domain_options[2], 7, "Correct element selection")
        self.assertTrue(domain_range.validate(random.choice(domain_range)), "Everything works")
