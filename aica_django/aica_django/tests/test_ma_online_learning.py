from django.test import TestCase


class OnlineLearningTestCase(TestCase):
    def setUp(self):
        return True

    def test_example(self):
        self.assertEqual(1, 1)
