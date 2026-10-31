import unittest
from prepare_sps_usb_capture import plan


class SpsPlanTests(unittest.TestCase):
    def test_unbound_plan_cannot_supply_capture_command(self):
        r=plan()
        self.assertIsNone(r['proposed_capture_arguments'])
        self.assertFalse(r['flashing_authorized'])
        self.assertFalse(r['serial_port_open'])

    def test_explicit_single_device_only(self):
        r=plan(r'\\.\USBPcap2',17)
        args=r['proposed_capture_arguments']
        self.assertEqual('17',args[args.index('--devices')+1])
        self.assertNotIn('-A',args)
        self.assertFalse(r['launch_performed'])
        self.assertFalse(r['topology_identity_verified'])
        self.assertEqual('-',args[args.index('-o')+1])
        self.assertTrue(r['capture_supervisor'].endswith('usbpcap_pipe_supervisor.py'))
        self.assertIn('DETACHED_PROCESS',r['supervisor_launch'])

    def test_invalid_or_partial_binding(self):
        for values in [(None,2),(r'\\.\USBPcap1',None),('USBPcap1',2),(r'\\.\USBPcap1',0),(r'\\.\USBPcap1',128)]:
            with self.assertRaises(ValueError):plan(*values)


if __name__=='__main__':unittest.main()
