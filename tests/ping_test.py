import unittest


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
		ans = self.socket._checksum('test'.encode())
		self.assertEqual(6182,ans)
	def testCheckSum_with_header(self):
		ans = self.socket._checksum(b'\x08\x00\x00\x01\x00\x01\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x61\x62\x63\x64\x65\x66\x67\x68\x69')
		self.assertEqual(19802,ans)
	def testCheckData_true(self):
		ans = self.socket._check_data(b'\x08\x00\x00\x01\x00\x01\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x61\x62\x63\x64\x65\x66\x67\x68\x69',19802)
		self.assertTrue(ans)
	def testCheckData_false(self):
		ans = self.socket._check_data(b'\x08\x00\x00\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x61\x62\x63\x64\x65\x66\x67\x68\x69',19802)
		self.assertFalse(ans)
	def testCreatePacket(self):
		request = ICMPRequest(
			destination='223.5.5.5',
			id=13009,
			sequence=0,
			payload=b'AAAA'
		)
		ans = self.socket._create_packet(request)
		self.assertEqual(b'\x08\x00B\xac2\xd1\x00\x00AAAA', ans)
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
