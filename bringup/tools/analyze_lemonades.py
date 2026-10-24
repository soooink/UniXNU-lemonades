#!/usr/bin/env python3
"""Analyze saved lemonades evidence on the host; this tool never calls ADB."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct


def cells(raw):
    if len(raw) % 4:
        raise ValueError('FDT cell value is not aligned')
    return list(struct.unpack('>' + 'I' * (len(raw) // 4), raw))


def text(raw):
    return raw.rstrip(b'\0').decode(errors='replace').replace('\0', ', ')


def fdt_nodes(data):
    if len(data) < 40:
        raise ValueError('Truncated FDT header')
    magic, total, offset, strings_offset, _, version, _, _, strings_size, size = struct.unpack_from('>10I', data)
    if magic != 0xd00dfeed or version != 17 or total > len(data):
        raise ValueError('Unsupported FDT header')
    if not (40 <= offset <= offset + size <= total and
            40 <= strings_offset <= strings_offset + strings_size <= total):
        raise ValueError('FDT sections out of bounds')
    strings = data[strings_offset:strings_offset + strings_size]
    position, limit, stack, nodes = offset, offset + size, [], {}
    while position + 4 <= limit:
        token = struct.unpack_from('>I', data, position)[0]
        position += 4
        if token == 1:
            end = data.find(b'\0', position, limit)
            if end == -1:
                raise ValueError('Unterminated FDT node')
            name = data[position:end].decode('ascii')
            if '/' in name or (not stack and name):
                raise ValueError('Invalid FDT node name')
            position = (end + 4) & ~3
            stack.append(name)
            path = '/'.join(stack) or '/'
            if path in nodes:
                raise ValueError('Duplicate FDT node')
            nodes[path] = {}
        elif token == 2:
            if not stack:
                raise ValueError('Unbalanced FDT nodes')
            stack.pop()
        elif token == 3:
            if not stack or position + 8 > limit:
                raise ValueError('FDT property outside a node')
            length, name_offset = struct.unpack_from('>II', data, position)
            position += 8
            end = strings.find(b'\0', name_offset)
            if end == -1 or position + length > limit:
                raise ValueError('FDT property out of bounds')
            key = strings[name_offset:end].decode('ascii')
            properties = nodes['/'.join(stack) or '/']
            if key in properties:
                raise ValueError('Duplicate FDT property')
            properties[key] = data[position:position + length]
            position = (position + length + 3) & ~3
        elif token == 4:
            continue
        elif token == 9:
            if stack or '/' not in nodes:
                raise ValueError('Incomplete FDT tree')
            return nodes
        else:
            raise ValueError('Invalid FDT token')
    raise ValueError('FDT end token missing')


def reg_ranges(nodes, path):
    parent = path.rsplit('/', 1)[0] or '/'
    address_cells = cells(nodes[parent].get('#address-cells', struct.pack('>I', 2)))[0]
    size_cells = cells(nodes[parent].get('#size-cells', struct.pack('>I', 1)))[0]
    if address_cells not in (1, 2) or size_cells not in (0, 1, 2):
        raise ValueError('Unsupported FDT address/size encoding')
    values = cells(nodes[path].get('reg', b''))
    stride = address_cells + size_cells
    if len(values) % stride:
        raise ValueError('Incomplete FDT register range')
    ranges = []
    for index in range(0, len(values), stride):
        address, size = 0, 0
        for value in values[index:index + address_cells]:
            address = address << 32 | value
        for value in values[index + address_cells:index + stride]:
            size = size << 32 | value
        ranges.append({'address': hex(address), 'size': hex(size), 'size_bytes': size})
    return ranges


def boot_v2(data):
    if len(data) < 1660 or data[:8] != b'ANDROID!':
        raise ValueError('Truncated Android boot header')
    kernel, kernel_address, ramdisk, ramdisk_address, second, second_address, tags, page, version, _ = struct.unpack_from('<10I', data, 8)
    if version != 2 or struct.unpack_from('<I', data, 1644)[0] != 1660:
        raise ValueError('Only the observed v2/1660-byte boot header is supported')
    if not kernel or not 2048 <= page <= 65536 or page & (page - 1):
        raise ValueError('Invalid boot image page size or empty kernel')
    align = lambda size: (size + page - 1) // page * page
    offset, segments = page, {}
    for name, size, address in (('kernel', kernel, kernel_address), ('ramdisk', ramdisk, ramdisk_address),
                                ('second', second, second_address)):
        if offset + size > len(data):
            raise ValueError('Truncated ' + name)
        segments[name] = {'file_offset': offset, 'bytes': size, 'header_load_address': hex(address)}
        offset += align(size)
    recovery_size, recovery_offset = struct.unpack_from('<IQ', data, 1632)
    if recovery_size and (recovery_offset != offset or recovery_offset + recovery_size > len(data)):
        raise ValueError('Invalid recovery DTBO range')
    offset += align(recovery_size)
    dtb_size, dtb_address = struct.unpack_from('<IQ', data, 1648)
    if not dtb_size or offset + dtb_size > len(data):
        raise ValueError('Truncated or empty boot DTB')
    segments['dtb'] = {'file_offset': offset, 'bytes': dtb_size, 'header_load_address': hex(dtb_address)}
    segments['recovery_dtbo'] = {'file_offset': recovery_offset, 'bytes': recovery_size}
    return {'header_version': version, 'header_bytes': 1660, 'page_bytes': page,
            'tags_header_address': hex(tags), 'segments': segments,
            'kernel_format': 'gzip' if data[page:page + 2] == b'\x1f\x8b' else 'uncompressed/other',
            'note': 'Header addresses are metadata; ABL relocation and BootShim addresses need separate validation.'}


def dtbo_entries(data):
    if len(data) < 32:
        raise ValueError('Truncated DTBO table')
    magic, total, header, entry_bytes, count, offset, page, version = struct.unpack_from('>8I', data)
    if (magic != 0xd7b7ab1e or version != 0 or header != 32 or entry_bytes != 32
            or not 1 <= count <= 4096 or not header <= offset
            or offset + count * entry_bytes > total or total > len(data)):
        raise ValueError('Invalid or unsupported DTBO table')
    entries = []
    for index in range(count):
        size, position, identifier, revision, *custom = struct.unpack_from('>8I', data, offset + index * entry_bytes)
        if position < offset + count * entry_bytes or position + size > total:
            raise ValueError('DTBO entry out of bounds')
        blob = data[position:position + size]
        fdt_nodes(blob)
        entries.append({'index': index, 'file_offset': position, 'bytes': size,
                        'id': hex(identifier), 'revision': hex(revision),
                        'custom': [hex(value) for value in custom],
                        'sha256': hashlib.sha256(blob).hexdigest()})
    return {'version': version, 'bytes': total, 'page_bytes': page, 'entries': entries}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    args = parser.parse_args()
    directory = args.collection.resolve()
    report = json.loads((directory / 'report.json').read_text())
    nodes = fdt_nodes((directory / 'running.dtb').read_bytes())
    cmdline = (directory / 'cmdline.txt').read_text().strip()
    selected_panel = re.search(r'(?:^|\s)msm_drm.dsi_display0=([^:\s]+)', cmdline)
    chosen_dtbo = re.search(r'(?:^|\s)androidboot.dtbo_idx=(\d+)', cmdline)
    selected_dtbo = int(chosen_dtbo[1]) if chosen_dtbo else None
    memory = {path: reg_ranges(nodes, path) for path, props in nodes.items()
              if props.get('device_type') == b'memory\0'}
    hardware = {}
    for path, props in nodes.items():
        if (props.get('compatible') == b'arm,gic-v3\0' or path == '/soc/ufshc@1d84000'
                or path == '/soc/timer' or path == '/reserved-memory/cont_splash_region@9c000000'
                or path.endswith('/fts@49')
                or selected_panel and path.rsplit('/', 1)[-1] == selected_panel[1]):
            hardware[path] = {key: text(value) if key in ('compatible', 'status', 'qcom,mdss-dsi-panel-name', 'fts,default-fw-name')
                              else [hex(cell) for cell in cells(value)]
                              for key, value in props.items() if key in (
                                  'compatible', 'status', 'reg', 'interrupts', 'redistributor-stride',
                                  'qcom,mdss-dsi-panel-name', 'qcom,mdss-dsi-panel-width',
                                  'qcom,mdss-dsi-panel-height', 'fts,default-fw-name')}
    reserved = []
    for path, props in nodes.items():
        if path.startswith('/reserved-memory/') and 'reg' in props:
            reserved.append({'path': path, 'ranges': reg_ranges(nodes, path),
                             'no_map': 'no-map' in props, 'status': text(props.get('status', b'okay\0'))})
    summary = {'format_version': 1, 'source': directory.name, 'identity': report['identity'],
               'memory_banks': memory, 'fixed_reserved_regions': reserved,
               'dynamic_reserved_regions': [path for path, props in nodes.items()
                                            if path.startswith('/reserved-memory/') and 'size' in props and 'reg' not in props],
               'cpu_affinities': [hex(int.from_bytes(props['reg'], 'big'))
                                  for path, props in nodes.items()
                                  if re.fullmatch(r'/cpus/cpu@[0-9a-f]+', path) and 'reg' in props],
               'psci_method': text(nodes.get('/psci', {}).get('method', b'')),
               'selected_panel_node': selected_panel[1] if selected_panel else None,
               'selected_dtbo_index': selected_dtbo, 'hardware_nodes': hardware,
               'root_layout': [dict(disk=disk, **part) for disk, disk_data in report['gpt'].items()
                               for part in disk_data.get('partitions', []) if part['name'] == 'userdata'],
               'boot_images': {}, 'notes': [
                   'Collected RAM banks and Linux reserved regions do not by themselves define safe UEFI allocation ranges.',
                   'No active framebuffer base/pitch was qualified; continuous-splash reg is a reserved window only.']}
    for name in ('boot', 'recovery'):
        data = (directory / (name + '.img')).read_bytes()
        parsed = boot_v2(data)
        summary['boot_images'][name] = parsed
        if name == 'boot':
            segment = parsed['segments']['dtb']
            (directory / 'boot-dtb.img').write_bytes(data[segment['file_offset']:segment['file_offset'] + segment['bytes']])
    data = (directory / 'dtbo.img').read_bytes()
    table = dtbo_entries(data)
    summary['dtbo_table'] = table
    if selected_dtbo is not None:
        if selected_dtbo >= len(table['entries']):
            raise ValueError('Selected DTBO index exceeds saved table')
        entry = table['entries'][selected_dtbo]
        (directory / ('dtbo-selected-' + str(selected_dtbo) + '.dtbo')).write_bytes(
            data[entry['file_offset']:entry['file_offset'] + entry['bytes']])
    path = directory / 'hardware-summary.json'
    path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + '\n')
    print('Saved ' + str(path))


if __name__ == '__main__':
    main()
