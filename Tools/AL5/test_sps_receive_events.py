import unittest
from emulate_sps_receive_events import Events
class ReceiveIdentityTests(unittest.TestCase):
 def test_changed_sps_rejected_before_native_allocation(self):
  with self.assertRaises(ValueError):Events(bytes(679828))
if __name__=='__main__':unittest.main()
