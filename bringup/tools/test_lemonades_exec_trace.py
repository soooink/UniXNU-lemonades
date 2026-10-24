import struct
import unittest
import zlib

from lemonades_exec_trace import decode_exec_trace


def packet(phase=3):
    values = [1, phase, 0x100004004, 0, 0x160000000, 20, 1, 0x100004000] + [0]*12
    rows = []
    for i, v in enumerate(values):
        crc = zlib.crc32(struct.pack("<BBQ", phase, i, v))
        rows.append(f"\nUMI EXEC {phase:02x} {i:02x} {v:016x} {crc:08x}\n".encode())
    return rows


def event_packet(phase, data):
    values = [1, phase] + list(data) + [0]*12
    assert len(values) == 20
    return b"".join(f"\nUMI EXEC {phase:02x} {i:02x} {v:016x} {zlib.crc32(struct.pack('<BBQ', phase, i, v)):08x}\n".encode()
                    for i, v in enumerate(values))


class ExecTraceTests(unittest.TestCase):
    def test_critical_child_exit_is_distinct_from_pid_one(self):
        name = struct.unpack("<4Q", b"critical_child\0".ljust(32, b"\0"))
        data = event_packet(8, [27, 78 << 8, 0, 0, 0, 0]) + event_packet(9, [1, 0, *name])
        event = decode_exec_trace(data)["critical_exit"]
        self.assertEqual(event["pid"], 27)
        self.assertEqual(event["name"], "critical_process_exit")
        self.assertEqual(event["process_name"], "critical_child")
        self.assertEqual(event["initproc_spawned"], 1)
        self.assertFalse(event["is_initproc"])
        self.assertEqual(event["exit_status"], 78)
        self.assertEqual(event["signal"], 0)
        self.assertEqual(event["description"], "")

    def test_exit_reason_requires_every_text_chunk(self):
        text = b"dyld: cache input unavailable; this text crosses one record boundary"
        meta = event_packet(8, [1, 9, 6, 1, 0, len(text)])
        first = event_packet(0x30, struct.unpack("<6Q", text[:48]))
        partial = decode_exec_trace(meta+first)["critical_exit"]
        self.assertNotIn("description", partial)
        self.assertEqual(partial["missing_text_chunks"], [1])
        second = event_packet(0x31, struct.unpack("<6Q", text[48:].ljust(48, b"\0")))
        full = decode_exec_trace(meta+first+second)["critical_exit"]
        self.assertEqual(full["description"], text.decode())
        self.assertEqual(full["reason_namespace"], 6)

    def test_oversized_exit_length_is_bounded(self):
        d = decode_exec_trace(event_packet(8, [1, 9, 6, 1, 0, 0xffffffff]))["critical_exit"]
        self.assertFalse(d["valid_description_length"])
        self.assertNotIn("description", d)

    def test_damaged_copies_do_not_replace_valid_values(self):
        good = packet()
        damaged = good[2].replace(b"0000000100004004", b"0000000100004005")
        d = decode_exec_trace(damaged+b"".join(good))
        self.assertEqual(d["crc_rejected_records"], 1)
        self.assertTrue(d["events"][0]["el0_svc_proved"])
        self.assertEqual(d["events"][0]["pc"], 0x100004004)

    def test_incomplete_record_cannot_prove_execution(self):
        d = decode_exec_trace(b"".join(packet()[:-1]))
        self.assertEqual(d["events"], [])
        self.assertEqual(d["incomplete_phases"], [3])

    def test_conflicting_valid_values_are_rejected(self):
        v = 0x100004008
        crc = zlib.crc32(struct.pack("<BBQ", 3, 2, v))
        other = f"\nUMI EXEC 03 02 {v:016x} {crc:08x}\n".encode()
        d = decode_exec_trace(b"".join(packet())+other)
        self.assertEqual(d["events"], [])
        self.assertEqual(d["conflicting_phases"], [3])


if __name__ == "__main__":
    unittest.main()
