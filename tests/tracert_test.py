import unittest

from tracert import tracert


class TracertTest(unittest.TestCase):
	def testTracert(self):
		hosts = tracert('223.5.5.5')
		self.assertGreater(len(hosts),1)


