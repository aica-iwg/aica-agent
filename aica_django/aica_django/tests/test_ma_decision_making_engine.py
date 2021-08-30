from django.test import TestCase
from aica_django.ma_decision_making_engine import handle_alert


class DecisionMakingEngineTestCase(TestCase):
    def setUp(self):
        return True

    def test_example(self):
        self.assertEqual(1, 1)
