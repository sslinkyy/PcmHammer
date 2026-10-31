import unittest
from emulate_sps_status_boundary import StatusProbe
class StatusIdentityTests(unittest.TestCase):
 def test_firmware_rejected_before_native_allocation(self):
  with self.assertRaises(ValueError):StatusProbe(bytes(679828),0)
if __name__=='__main__':unittest.main()
