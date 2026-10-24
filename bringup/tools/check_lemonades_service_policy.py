#!/usr/bin/env python3
"""Run the real policy initializer with the exact selected tablet job list."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import subprocess
import tomllib

from test_lemonades_watchdog_policy import PREFIX, SOURCE, validate_delta

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--reference', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    config = ROOT/'devices/lemonades/package/unixnu-xnu-prelink.toml'
    args = next(e['args'] for e in tomllib.loads(config.read_text())['entry'] if e['id'] == 'xnu').split()
    wanted = [s for s in tomllib.loads(a.reference.read_text())['payload']['kernel_args']
              if s.startswith('sheng-disable-jobs=')]
    actual = [s for s in args if s.startswith('sheng-disable-jobs=')]
    assert len(actual) == 1 and actual == wanted
    assert args.count('sheng-disable-watchdogd=1') == 1
    assert not any(s.startswith(('sheng-data-reset=', 'sheng-setup=')) for s in args)
    jobs = actual[0].split('=', 1)[1]
    assert len(jobs) < 200 and all(c.isalnum() or c in '.-,' for c in jobs)
    expected = {'com.apple.watchdogd': True, **{job: True for job in jobs.split(',')}}
    assert len(expected) == 5
    assert 'com.apple.chronod' not in expected
    evidence = validate_delta()
    body = SOURCE.read_text()
    body = body[body.index('static const char policy'):]
    main_source = r'''
static unsigned char scratch[4096];
int main(void) {
 enabled=1;
 strcpy(job_args,JOB_LIST);
 memset(scratch+0x400,0x5a,0x400);
 assert(!sheng_boot_watchdog_policy(NULL,(uintptr_t)scratch));
 assert(written_size<512 && written_size==strlen(policy));
 for(unsigned i=0x400;i<0x800;++i)assert(scratch[i]==0x5a);
 unsigned char first[1024];size_t size=written_size;
 memcpy(first,written_data,sizeof(first));
 assert(!sheng_boot_watchdog_policy(NULL,(uintptr_t)scratch));
 assert(written_size==size && !memcmp(first,written_data,size));
 for(unsigned i=0x400;i<0x800;++i)assert(scratch[i]==0x5a);
 assert(opens==4 && closes==3 && !sheng_watchdog_policy_status);
 /* Removing the job argument next boot restores the watchdog-only policy. */
 job_args[0]=0;
 assert(!sheng_boot_watchdog_policy(NULL,(uintptr_t)scratch));
 assert(written_size<size);
 for(size_t i=written_size;i<sizeof(written_data);++i)assert(!written_data[i]);
 assert(fwrite(first,1,size,stdout)==size);
 return 0;
}
'''.replace('JOB_LIST', json.dumps(jobs))
    a.out.mkdir(parents=True, exist_ok=True)
    source = a.out/'service-policy.c'
    binary = a.out/'service-policy'
    source.write_text(PREFIX+body+main_source)
    subprocess.run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O1', '-g',
                    '-fsanitize=address,undefined', str(source), '-o', str(binary)], check=True, timeout=45)
    r = subprocess.run([str(binary)], capture_output=True, timeout=10)
    (a.out/'stderr.log').write_bytes(r.stderr)
    if r.returncode:
        raise RuntimeError(r.stderr.decode(errors='replace'))
    assert plistlib.loads(r.stdout) == expected
    (a.out/'expected-disabled.plist').write_bytes(r.stdout)
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    result = dict(evidence, passed=True, config_sha256=sha(config),
                  reference_sha256=sha(a.reference), checker_sha256=sha(Path(__file__)),
                  disabled=expected, generated_policy_bytes=len(r.stdout),
                  unchanged_environment_slots=True, repeated_boot=True,
                  removal_on_subsequent_boot=True, original_initializer_executed=True,
                  syscalls_substituted=True, sanitizer='address,undefined',
                  phone_policy_observed=False, qemu_test_performed=False)
    (a.out/'report.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
