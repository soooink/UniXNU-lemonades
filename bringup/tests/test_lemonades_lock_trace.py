import struct
import sys
import unittest
import zlib
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from lemonades_lock_trace import decode_lock_trace


def record(index,value):
    crc=zlib.crc32(struct.pack("<BBQ",1,index,value))
    return f"\nUMI LOCK 01 {index:02x} {value:016x} {crc:08x}\n".encode()


class LockTraceTests(unittest.TestCase):
    def data(self,omit=None):
        values={0:1,1:0xfffffff012345600,2:0,3:0,4:0,5:0,6:0x3c0,
                7:0xfffffff056789000,8:16,9:2,10:0xfffffff011112224,
                11:0xfffffff022223334,58:1400}
        return b"".join(record(i,v) for i,v in values.items() if i != omit)

    def test_corrupted_copy_cannot_supply_a_frame(self):
        data=self.data()
        bad=data.replace(b"fffffff011112224",b"fffffff011112225")
        decoded=decode_lock_trace(bad+data)
        self.assertEqual(decoded["event"]["return_addresses"][0],0xfffffff011112224)
        self.assertEqual(decoded["crc_rejected_records"],1)

    def test_missing_frame_prevents_complete_event(self):
        decoded=decode_lock_trace(self.data(11))
        self.assertIsNone(decoded["event"])
        self.assertIn(11,decoded["missing_required_fields"])

    def test_conflicting_valid_state_is_rejected(self):
        decoded=decode_lock_trace(self.data()*5+record(5,1))
        self.assertIsNone(decoded["event"])
        self.assertIn(5,decoded["conflicting_fields"])


if __name__=="__main__":
    unittest.main()
