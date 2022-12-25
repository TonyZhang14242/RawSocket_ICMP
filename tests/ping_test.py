import sys
import unittest


sys.path.append("..")
from models import ICMPRequest
from ping import ping
from sockets import ICMPSocket
class PingTest(unittest.TestCase):
	socket = None
	@classmethod
	def setUpClass(cls):
		cls.socket = ICMPSocket()

	@classmethod
	def tearDownClass(cls):
		cls.socket.close()
	def testCheckSum_basic(self):
		ans = self.socket._checksum(b'\x08\x00\x00\x00\x04\x00\x00\x01abcd')
		self.assertEqual(12088,ans)
	def testCheckSum_with_random_param(self):
		ans = self.socket._checksum(b'\x08\x00\x00\x00\x03\x81\x00\x01kdzqdOFsgHIK60OuuSEwNo7ps7v7P78mRCLjg5dVw3IzPu58PD25ADtL')
		self.assertEqual(37455,ans)
	def testCheckData_true(self):
		ans = self.socket._check_data(b'\x08\x00\x00\x00E9\x00\x01zIFGqgWafHAmyLx4q7370PGW4S6633gAKMJWzqW1H9JA5w0E1FiGZdD3',54909)
		self.assertTrue(ans)
	def testCheckData_false(self):
		ans = self.socket._check_data(b'\x08\x00\x00\x00E9\x00\x01zIFGqgWafHAmyLx4q7370PGW4S661H9JA5w0E1asfasfgdsasFiGZdD3',54909)
		self.assertFalse(ans)
	def testCreatePacket(self):
		request = ICMPRequest(
			destination='223.5.5.5',
			id=13009,
			sequence=1,
			payload=b'AAAA'
		)
		ans = self.socket._create_packet(request)
		self.assertEqual(b'\x08\x00B\xab2\xd1\x00\x01AAAA', ans)
	def testParsePacket_normal(self):
		reply = self.socket._parse_reply(b'E\x00\x00T.d\x00\x00/\x01\xad\xdd\xb2\x9d:\xbb\xc0\xa8\x01g\x00\x00\xdcKJ\x95\x00\x00GoQOrJrWZA5V82mrPkOtQrjXf07EZeNdYZkwNZ7ReHx7kwzlowcfArbf','223.5.5.5',1669111491.8911805)
		self.assertEqual(19093,reply.id)
		self.assertEqual(0,reply.sequence)
		self.assertEqual(0,reply.type)
		self.assertEqual(0,reply.code)
	def testParsePacket_error(self):
		reply = self.socket._parse_reply(b'E\x00\x00p\x00\x05\x00\x00\x80\x01\x00\x00\xc0\xa8\x01g\xc0\xa8\x01g\x03\x01%\xaa\x00\x00\x00\x00E\x00\x00T\xcd\x8a\x00\x00@\x01\x00\x00\xc0\xa8\x01g\xc0\xa8\x01\xbc\x08\x00T\xd5\x0eU\x00\x001h3fn0ueYjgR06TdC5yGzZwegKtJDWazgVHqsVi4frLZ0jVz2MXENk8t','223.5.5.5',1669111491.8911805)
		self.assertEqual(3669,reply.id)
		self.assertEqual(0,reply.sequence)
		self.assertEqual(3,reply.type)
		self.assertEqual(1,reply.code)
	def testPing_basic(self):
		host = ping('223.5.5.5',5)
		self.assertIsNotNone(host)



if __name__ == '__main__':
	unittest.main()
