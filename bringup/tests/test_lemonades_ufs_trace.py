import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location("ufs",Path(__file__).parents[1]/"tools/lemonades_ufs_trace.py")
ufs=importlib.util.module_from_spec(spec)
spec.loader.exec_module(ufs)
def records(values):
    return [{"stage":hex(0xe0+i),"value":hex(v)} for i,v in enumerate(values)]
class UfsTraceTest(unittest.TestCase):
    def test_versions_and_completion(self):
        a=[1,5,0,1]+[0]*28
        b=[2,9,0,1]+[0]*28
        c=[3,15,0,10]+[0]*28
        result=ufs.phone_events(records(a)+records(b)+records(c))
        self.assertEqual(len(result["events"]),1)
        self.assertEqual(result["smmu_events"][0]["phase"],9)
        self.assertTrue(result["disk_read_tested"])
        self.assertFalse(result["root_mounted"])
    def test_never_splice_truncated_records(self):
        a=[3,15,0,10]+[0]*28
        b=[3,10,0xe00002d6,1]+[0]*28
        result=ufs.phone_events(records(a)[:17]+records(b))
        self.assertEqual(result["incomplete_groups"],1)
        self.assertFalse(result["disk_read_tested"])
        self.assertEqual(len(result["read_events"]),1)
    def test_unknown_not_a_pass(self):
        result=ufs.phone_events(records([99,15,0,10]+[0]*28))
        self.assertFalse(result["disk_read_tested"])
        self.assertEqual(len(result["unknown_versions"]),1)
    def test_native_provider_does_not_claim_mount(self):
        values=[4,3,1,1,1,1,0,7]+[0]*24
        result=ufs.phone_events(records(values))
        self.assertTrue(result["disk_read_tested"])
        self.assertFalse(result["root_mounted"])
        values[2]=0
        self.assertFalse(ufs.phone_events(records(values))["disk_read_tested"])
if __name__=="__main__": unittest.main()
