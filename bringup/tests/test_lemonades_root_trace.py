import struct
import sys
import unittest
import zlib
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from lemonades_root_trace import decode_root_trace


def record(phase,field,value):
    crc=zlib.crc32(struct.pack("<BBQ",phase,field,value))
    return f"\nUMI ROOT {phase:02x} {field:02x} {value:016x} {crc:08x}\n".encode()


class RootTraceTests(unittest.TestCase):
    def test_damaged_copies_cannot_change_result(self):
        good=b"".join(record(2,i,2 if i==0 else i+10) for i in range(18))
        bad=good.replace(b"000000000000000b",b"000000000000000f")
        d=decode_root_trace(bad+good+bad)
        self.assertEqual(len(d["events"]),1)
        self.assertEqual(d["events"][0]["trust_enabled"],11)
        self.assertEqual(d["crc_rejected_records"],2)

    def test_missing_field_never_qualifies(self):
        d=decode_root_trace(b"".join(record(1,i,1) for i in range(17)))
        self.assertFalse(d["events"])
        self.assertEqual(d["incomplete_phases"],[1])

    def test_conflicting_valid_values_are_not_majority_voted(self):
        data=b"".join(record(2,i,2) for i in range(18))
        d=decode_root_trace(data*5+record(2,4,0))
        self.assertFalse(d["events"])
        self.assertEqual(d["conflicting_phases"],[2])


if __name__=="__main__":
    unittest.main()
