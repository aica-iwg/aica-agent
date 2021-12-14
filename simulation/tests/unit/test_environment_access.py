import unittest

from cyst.api.logic.access import AccessLevel
from cyst.api.environment.environment import Environment

# TODO : can we just delete this?
"""
 #  Policies and authorizations have been revamped since, these test have use no more.
class TestPolicy(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls._env = Environment.create()
        cls._conf = cls._env.configuration.node
        cls._policy = cls._env.policy

        # Access to services s1 and s2 on each node
        a1 = cls._policy.create_authorization("id1", [], ["s1", "s2"], AccessLevel.ELEVATED)
        # Access to all services on node n1
        a2 = cls._policy.create_authorization("id2", ["n1"], [], AccessLevel.ELEVATED)
        # Access to services s1 and s2 on nodes n1, n2, n3
        a3 = cls._policy.create_authorization("id3", ["n1", "n2", "n3"], ["s1", "s2"], AccessLevel.ELEVATED)
        # Access to everything
        a4 = cls._policy.create_authorization("id4", [], [], AccessLevel.ELEVATED)

        cls._policy.add_authorization(a1, a2, a3, a4)

    def test_decide(self):
        n1 = self._conf.create_node("n1")
        n2 = self._conf.create_node("n2")
        t1 = self._policy.create_authorization("id1", ["n1"], ["s1"], AccessLevel.LIMITED)
        self._policy.add_authorization(t1)

        self.assertTrue(self._policy.decide("n1", "s1", AccessLevel.NONE, t1)[0], "Authorization with greater access level")
        self.assertTrue(self._policy.decide("n1", "s1", AccessLevel.LIMITED, t1)[0], "Authorization with equal access level")
        self.assertFalse(self._policy.decide("n1", "s1", AccessLevel.ELEVATED, t1)[0], "Authorization with lower access level")
        self.assertFalse(self._policy.decide("n2", "s1", AccessLevel.NONE, t1)[0], "Authorization for wrong node")


if __name__ == '__main__':
    unittest.main()
"""