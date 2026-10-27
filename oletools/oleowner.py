#!/usr/bin/env python
"""
oleowner

oleowner parses OLE2 (Compound File Binary) files, including partially
corrupted ones, and builds a deterministic sector ownership graph which
correlates the DIFAT, FAT, Directory, MiniFAT, the root Mini Stream, normal
streams and mini streams.

For every FAT sector and every mini sector it records one or more owners, and
it reports:
  - cross-occupied sectors (claimed by several owners or claimed while marked
    free/reserved in the allocation table)
  - allocation cycles
  - out-of-bounds chain pointers (beyond the allocation table and/or beyond
    the physical end of file)
  - orphan chains (allocated but unreachable from any directory entry or
    structural chain)
  - size/chain-length mismatches and orphan directory entries

When a chain is corrupted, only the verified prefix is reported: every sector
of the prefix is physically present, in bounds, and reached by following the
on-disk allocation entries from the declared start. Ownership of the prefix
is still recorded, so cross-occupancy against the salvaged prefix is detected.

Author: Philippe Lagadec - http://www.decalage.info
License: BSD, see source code or documentation

oleowner is part of the python-oletools package:
http://www.decalage.info/python/oletools
"""

#=== LICENSE ==================================================================

# oleowner is copyright (c) 2024 Philippe Lagadec (http://www.decalage.info)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#  * Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from __future__ import print_function

# === IMPORTS ================================================================

import sys, os, json, optparse, struct

# IMPORTANT: it should be possible to run oletools directly as scripts in any
# directory without installing them with pip or setup.py. Relative imports are
# not usable in that case, so the oletools parent folder is added to sys.path:
_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
_parent_dir = os.path.normpath(os.path.join(_thismodule_dir, '..'))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

import olefile
from oletools.thirdparty.tablestream import tablestream
from oletools.thirdparty.xglob import xglob

__version__ = '0.61.dev1'

BANNER = 'oleowner %s - http://decalage.info/python/oletools' % __version__

# === CONSTANTS ==============================================================

# Special FAT/MiniFAT values, see [MS-CFB] 2.2 / olefile:
FREESECT = olefile.FREESECT          # 0xFFFFFFFF: free (MiniFAT: NOSTREAM)
ENDOFCHAIN = olefile.ENDOFCHAIN      # 0xFFFFFFFE
FATSECT = olefile.FATSECT            # 0xFFFFFFFD: FAT sector
DIFSECT = olefile.DIFSECT            # 0xFFFFFFFC: DIFAT sector
MAXREGSECT = 0xFFFFFFFA              # greatest regular sector id
NOSTREAM = olefile.NOSTREAM          # 0xFFFFFFFF: no directory sibling/child

STGTY_EMPTY = olefile.STGTY_EMPTY
STGTY_STORAGE = olefile.STGTY_STORAGE
STGTY_STREAM = olefile.STGTY_STREAM
STGTY_LOCKBYTES = olefile.STGTY_LOCKBYTES
STGTY_PROPERTY = olefile.STGTY_PROPERTY
STGTY_ROOT = olefile.STGTY_ROOT

OLE_SIGNATURE = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
HEADER_SIZE = 512
DIRENFMT = '<64sHBBIII16sIQQIII'
DIRENTRY_SIZE = 128
MINI_SECTOR_SIZE = 64
EXPECTED_CUTOFF = 0x1000
DIFAT_IN_HEADER = 109

# Planes
PLANE_FAT = 'fat'
PLANE_MINI = 'minifat'

# Anomaly severities (deterministic ordering in text reports follows the
# discovery order; severity is only used for the summary/exit status):
SEV_ERROR = 'ERROR'
SEV_WARN = 'WARN'
SEV_INFO = 'INFO'

# Chain terminal status:
ST_OK = 'ok'
ST_TRUNCATED = 'truncated'       # ENDOFCHAIN reached before expected length
ST_LONG = 'long_chain'           # expected length reached without ENDOFCHAIN
ST_CYCLE = 'cycle'
ST_OOB_TABLE = 'out_of_table'    # pointer beyond allocation table
ST_OOB_FILE = 'beyond_eof'       # pointer beyond physical file
ST_RESERVED = 'reserved_target'  # pointer to FATSECT/DIFSECT/unknown special
ST_FREE_TARGET = 'free_target'   # pointer to a FREESECT
ST_HEAD_OOB = 'head_out_of_bounds'
ST_HEAD_SPECIAL = 'head_special'
ST_CROSS = 'joins_other_owner'   # chain enters a sector owned elsewhere
ST_UNBOUNDED = 'unterminated'    # ran past the hard safety bound

SPECIAL_NAMES = {
    FREESECT: 'FREESECT',
    ENDOFCHAIN: 'ENDOFCHAIN',
    FATSECT: 'FATSECT',
    DIFSECT: 'DIFSECT',
}

ENTRY_TYPE_NAMES = {
    STGTY_EMPTY: 'Empty',
    STGTY_STORAGE: 'Storage',
    STGTY_STREAM: 'Stream',
    STGTY_LOCKBYTES: 'ILockBytes',
    STGTY_PROPERTY: 'IPropertyStorage',
    STGTY_ROOT: 'Root',
}


# === LOW-LEVEL HELPERS ======================================================

def _u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def _is_special(value):
    return value > MAXREGSECT


def _marker(value):
    """Render a FAT/MiniFAT entry for reports (special name or hex value)."""
    return SPECIAL_NAMES.get(value, '%08X' % value)


def _owner(kind, ident, label):
    """An owner of one or more sectors."""
    return {'kind': kind, 'id': ident, 'label': label}


def _read_sector(data, sector_size, sid):
    """
    Read one big sector (sector 0 starts right after the 512-byte header).
    Returns (bytes_or_None, truncated_bool).
    """
    start = sector_size * (sid + 1)
    chunk = data[start:start + sector_size]
    if len(chunk) == 0:
        return None, False
    if len(chunk) < sector_size:
        return chunk + b'\x00' * (sector_size - len(chunk)), True
    return chunk, False


def _u32_array(sector):
    return list(struct.unpack('<%dI' % (len(sector) // 4), sector))


# === ANOMALY TRACKER ========================================================

class Report(object):
    """Holds the full result of an ownership analysis."""

    def __init__(self, filename=None):
        self.filename = filename
        self.fatal = None            # message if the file cannot be analysed
        self.header = None
        self.chains = []             # verified chains, in discovery order
        self.anomalies = []          # deterministic discovery order
        # big sectors: sid -> list of (owner dict, ordinal)
        self.big_claims = {}
        # mini sectors: mini sid -> list of (owner dict, ordinal)
        self.mini_claims = {}
        # tails of every verified chain, as (plane, owner id, sid)
        self.chain_tails = set()
        self.big_sector_map = []     # filled at finalization
        self.mini_sector_map = []

    def anomaly(self, severity, kind, location=None, message='', owner=None):
        """Record an anomaly. location is a dict with plane/sid/etc."""
        self.anomalies.append({
            'severity': severity,
            'kind': kind,
            'location': location or {},
            'message': message,
            'owner': owner,
        })

    def summary(self):
        counts = {SEV_ERROR: 0, SEV_WARN: 0, SEV_INFO: 0}
        kinds = {}
        for a in self.anomalies:
            counts[a['severity']] = counts.get(a['severity'], 0) + 1
            kinds[a['kind']] = kinds.get(a['kind'], 0) + 1
        return {
            'chains': len(self.chains),
            'big_sectors': len(self.big_sector_map),
            'mini_sectors': len(self.mini_sector_map),
            'errors': counts[SEV_ERROR],
            'warnings': counts[SEV_WARN],
            'infos': counts[SEV_INFO],
            'kinds': dict(sorted(kinds.items())),
        }

    def to_dict(self):
        return {
            'file': self.filename,
            'fatal': self.fatal,
            'header': self.header,
            'summary': self.summary(),
            'chains': self.chains,
            'anomalies': self.anomalies,
            'big_sectors': self.big_sector_map,
            'mini_sectors': self.mini_sector_map,
        }


# === RAW OLE PARSING ========================================================

def parse_header(data, report):
    """Parse the 512-byte OLE header. Returns a header dict or None."""
    if len(data) < HEADER_SIZE:
        report.fatal = 'file too small to contain an OLE2 header (%d bytes)' \
                       % len(data)
        return None
    raw = data[:HEADER_SIZE]
    if raw[:8] != OLE_SIGNATURE:
        report.fatal = 'not an OLE2 file: bad signature %r' % raw[:8]
        return None
    sector_shift = struct.unpack_from('<H', raw, 30)[0]
    mini_shift = struct.unpack_from('<H', raw, 32)[0]
    if sector_shift not in (9, 12):
        report.fatal = 'unsupported sector shift %d (expected 9 or 12)' \
                       % sector_shift
        return None
    sector_size = 1 << sector_shift
    mini_sector_size = 1 << mini_shift if mini_shift else MINI_SECTOR_SIZE
    hdr = {
        'raw': raw,
        'minor_version': struct.unpack_from('<H', raw, 24)[0],
        'dll_version': struct.unpack_from('<H', raw, 26)[0],
        'byte_order': struct.unpack_from('<H', raw, 28)[0],
        'sector_shift': sector_shift,
        'sector_size': sector_size,
        'mini_sector_shift': mini_shift,
        'mini_sector_size': mini_sector_size,
        'num_dir_sectors': _u32(raw, 40),
        'num_fat_sectors': _u32(raw, 44),
        'first_dir_sector': _u32(raw, 48),
        'mini_cutoff': _u32(raw, 56),
        'first_minifat_sector': _u32(raw, 60),
        'num_minifat_sectors': _u32(raw, 64),
        'first_difat_sector': _u32(raw, 68),
        'num_difat_sectors': _u32(raw, 72),
    }
    file_size = len(data)
    hdr['file_size'] = file_size
    # layout: 1 header sector + N data sectors
    hdr['nb_sect'] = max(0, file_size // sector_size - 1)
    hdr['trailing_bytes'] = file_size - HEADER_SIZE \
        - hdr['nb_sect'] * sector_size

    if hdr['byte_order'] != 0xFFFE:
        report.anomaly(SEV_WARN, 'header_bad_byte_order',
                       message='byte order is %04X, expected FFFE'
                               % hdr['byte_order'])
    if hdr['mini_cutoff'] != EXPECTED_CUTOFF:
        report.anomaly(SEV_WARN, 'header_bad_cutoff',
                       message='mini stream cutoff is %d, expected %d'
                               % (hdr['mini_cutoff'], EXPECTED_CUTOFF))
    if sector_size == 512 and hdr['num_dir_sectors'] != 0:
        report.anomaly(SEV_WARN, 'header_dir_sector_count',
                       message='#dir sectors is %d, should be 0 with 512-byte '
                               'sectors' % hdr['num_dir_sectors'])
    if mini_sector_size != MINI_SECTOR_SIZE:
        report.anomaly(SEV_WARN, 'header_bad_mini_shift',
                       message='mini sector size is %d, expected %d'
                               % (mini_sector_size, MINI_SECTOR_SIZE))
    return hdr


def load_fat(data, hdr, report):
    """
    Recover the DIFAT/FAT layout without trusting any pointer.

    Returns (fat_list, fat_sector_sids_in_order, difat_sector_sids_in_order).
    Missing/unreadable FAT sectors are padded with FREESECT so that indices
    stay stable; every problem is recorded as an anomaly.
    """
    ss = hdr['sector_size']
    entries_per = ss // 4
    nb_sect = hdr['nb_sect']

    # 1) up to 109 FAT sector ids stored in the header DIFAT array
    difat_heads = []
    for i in range(DIFAT_IN_HEADER):
        value = _u32(hdr['raw'], 76 + 4 * i)
        if value == FREESECT:
            break
        if value == ENDOFCHAIN:
            break
        difat_heads.append(value)

    # 2) the DIFAT chain itself
    difat_sids = []
    difat_slots = []          # FAT sector ids read from DIFAT sectors
    cur = hdr['first_difat_sector']
    declared = hdr['num_difat_sectors']
    if declared > 0:
        seen = set()
        if _is_special(cur):
            report.anomaly(SEV_ERROR, 'difat_head_special',
                           {'plane': PLANE_FAT, 'sid': cur},
                           'first DIFAT sector is %s' % _marker(cur))
            cur = None
        guard = 0
        while cur is not None and guard <= declared:
            guard += 1
            if cur >= nb_sect:
                report.anomaly(SEV_ERROR, 'difat_out_of_bounds',
                               {'plane': PLANE_FAT, 'sid': cur},
                               'DIFAT sector %d beyond end of file (%d '
                               'sectors)' % (cur, nb_sect))
                break
            if cur in seen:
                report.anomaly(SEV_ERROR, 'difat_cycle',
                               {'plane': PLANE_FAT, 'sid': cur},
                               'DIFAT chain loops back to sector %d' % cur)
                break
            seen.add(cur)
            difat_sids.append(cur)
            sector, truncated = _read_sector(data, ss, cur)
            if truncated:
                report.anomaly(SEV_WARN, 'truncated_sector',
                               {'plane': PLANE_FAT, 'sid': cur},
                               'DIFAT sector %d is shorter than %d bytes'
                               % (cur, ss))
            entries = _u32_array(sector)
            slots = entries[:entries_per - 1]
            for value in slots:
                if value == FREESECT or value == ENDOFCHAIN:
                    break
                difat_slots.append(value)
            cur = entries[entries_per - 1]
            if len(difat_sids) == declared:
                if cur not in (ENDOFCHAIN, FREESECT):
                    report.anomaly(SEV_WARN, 'difat_long_chain',
                                   {'plane': PLANE_FAT, 'sid': cur},
                                   'declared %d DIFAT sectors but chain '
                                   'continues to %s'
                                   % (declared, _marker(cur)))
                break
        else:
            if len(difat_sids) < declared:
                report.anomaly(SEV_ERROR, 'difat_short_chain',
                               message='declared %d DIFAT sectors but only %d '
                                       'are reachable'
                                       % (declared, len(difat_sids)))

    fat_sids = difat_heads + difat_slots

    if hdr['num_fat_sectors'] != len(fat_sids):
        report.anomaly(SEV_WARN, 'fat_count_mismatch',
                       message='header declares %d FAT sector(s) but DIFAT '
                               'lists %d'
                               % (hdr['num_fat_sectors'], len(fat_sids)))

    seen_fat = set()
    fat = []
    for ordinal, sid in enumerate(fat_sids):
        if sid in seen_fat:
            report.anomaly(SEV_ERROR, 'fat_sector_listed_twice',
                           {'plane': PLANE_FAT, 'sid': sid},
                           'FAT sector %d is listed twice in the DIFAT'
                           % sid)
        seen_fat.add(sid)
        if sid >= nb_sect:
            report.anomaly(SEV_ERROR, 'fat_sector_out_of_bounds',
                           {'plane': PLANE_FAT, 'sid': sid},
                           'FAT sector %d is beyond end of file' % sid)
            fat.extend([FREESECT] * entries_per)
            continue
        sector, truncated = _read_sector(data, ss, sid)
        if truncated:
            report.anomaly(SEV_WARN, 'truncated_sector',
                           {'plane': PLANE_FAT, 'sid': sid},
                           'FAT sector %d is shorter than %d bytes'
                           % (sid, ss))
        fat.extend(_u32_array(sector))

    if not fat:
        report.anomaly(SEV_ERROR, 'fat_empty',
                       message='DIFAT does not reference any FAT sector')
        fat = [FREESECT] * entries_per
    return fat, fat_sids, difat_sids


def walk_chain(table, start, expected=None, phys_bound=None,
               hard_bound=None):
    """
    Defensively walk an allocation chain.

    :param table: FAT or MiniFAT list of uint32 entries
    :param start: first sector id declared by the owner
    :param expected: expected number of sectors (declared size), or None for
        chains terminated by ENDOFCHAIN (directory)
    :param phys_bound: sectors with id >= phys_bound are not physically present
    :param hard_bound: safety cap on chain length (defaults to len(table))
    :returns: dict(prefix=[...], events=[(kind, sid, value)], status=...)

    The returned prefix contains only verified sectors: each link in the
    prefix comes from the on-disk table, every id is regular, within the
    table and within the physical file. Walking stops at the first fault and
    the verifiable prefix is always preserved.
    """
    events = []
    prefix = []
    table_bound = len(table)
    if hard_bound is None:
        hard_bound = table_bound

    def finish(status):
        return {'prefix': prefix, 'events': events, 'status': status}

    if _is_special(start):
        events.append(('head_special', None, start))
        return finish(ST_HEAD_SPECIAL)
    if start >= table_bound:
        events.append(('head_out_of_table', None, start))
        return finish(ST_HEAD_OOB)
    if phys_bound is not None and start >= phys_bound:
        events.append(('head_beyond_eof', None, start))
        return finish(ST_HEAD_OOB)

    cur = start
    seen = set()
    while True:
        if cur in seen:
            events.append(('cycle', cur, cur))
            return finish(ST_CYCLE)
        seen.add(cur)
        prefix.append(cur)

        nxt = table[cur] & 0xFFFFFFFF

        # a loop back into this chain is always a cycle, even when the
        # declared length has already been reached
        if nxt in seen:
            events.append(('cycle', cur, nxt))
            return finish(ST_CYCLE)
        if expected is not None and len(prefix) >= expected:
            if nxt != ENDOFCHAIN:
                events.append(('chain_long', cur, nxt))
                return finish(ST_LONG)
            return finish(ST_OK)

        if nxt == ENDOFCHAIN:
            if expected is not None and len(prefix) < expected:
                events.append(('early_end', cur, nxt))
                return finish(ST_TRUNCATED)
            return finish(ST_OK)
        if nxt == FREESECT:
            events.append(('free_target', cur, nxt))
            return finish(ST_FREE_TARGET)
        if nxt in (FATSECT, DIFSECT) or nxt > MAXREGSECT:
            events.append(('reserved_target', cur, nxt))
            return finish(ST_RESERVED)
        if nxt >= table_bound:
            events.append(('link_out_of_table', cur, nxt))
            return finish(ST_OOB_TABLE)
        if phys_bound is not None and nxt >= phys_bound:
            events.append(('link_beyond_eof', cur, nxt))
            return finish(ST_OOB_FILE)
        if len(prefix) >= hard_bound:
            events.append(('unterminated', cur, nxt))
            return finish(ST_UNBOUNDED)
        cur = nxt


def parse_direntries(sector_bytes):
    """Parse raw directory sectors into a list of entry dicts."""
    entries = []
    for offset in range(0, len(sector_bytes) - DIRENTRY_SIZE + 1,
                        DIRENTRY_SIZE):
        raw = sector_bytes[offset:offset + DIRENTRY_SIZE]
        (name_raw, namelength, etype, color, left, right, child, clsid,
         flags, ctime, mtime, start, size_low, size_high) = \
            struct.unpack(DIRENFMT, raw)
        if namelength > 64:
            namelength = 64
        name_bytes = name_raw[:max(0, namelength - 2)]
        try:
            name = name_bytes.decode('utf-16-le', errors='replace')
        except Exception:
            name = ''
        entries.append({
            'sid': len(entries),
            'name': name,
            'name_length': namelength,
            'type': etype,
            'color': color,
            'left': left,
            'right': right,
            'child': child,
            'clsid': '%08X' % 0,  # kept simple; identity comes from sid/name
            'start': start,
            'size_low': size_low,
            'size_high': size_high,
            'size': size_low + (size_high << 32),
        })
    return entries


# === OWNERSHIP GRAPH BUILDER ================================================

def analyze(data, filename=None):
    """
    Build the deterministic sector ownership graph of an OLE2 file given as
    bytes. Returns a Report object.
    """
    report = Report(filename)
    hdr = parse_header(data, report)
    if hdr is None:
        return report

    ss = hdr['sector_size']
    mini_ss = hdr['mini_sector_size']
    nb_sect = hdr['nb_sect']

    fat, fat_sids, difat_sids = load_fat(data, hdr, report)
    table_bound = len(fat)

    # header summary enriched with parsed layout counts
    report.header = {k: v for k, v in hdr.items() if k != 'raw'}
    report.header['fat_entries'] = table_bound
    report.header['fat_sectors'] = len(fat_sids)
    report.header['difat_sectors'] = len(difat_sids)

    # ---- claims helper ---------------------------------------------------
    def claim(plane, sid, owner, ordinal):
        """
        Record ownership of sid on the given plane. A sector claimed by two
        different owners is cross-occupied. The first conflict is reported;
        all claims are kept so the map is exhaustive.
        """
        claims = report.big_claims if plane == PLANE_FAT else \
            report.mini_claims
        existing = claims.setdefault(sid, [])
        # every claim is recorded so the map stays exhaustive even when
        # sectors are cross-occupied
        existing.append((owner, ordinal))
        conflict = False
        for other, _ord in existing:
            if other['id'] != owner['id'] or other['kind'] != owner['kind']:
                if not conflict:
                    report.anomaly(
                        SEV_ERROR, 'cross_occupied',
                        {'plane': plane, 'sid': sid},
                        'sector %s %d is owned by both %r and %r'
                        % (plane, sid, other['label'], owner['label']),
                        owner=owner)
                conflict = True
        if conflict:
            # caller must stop walking so it does not traverse the other
            # owner's tail
            return False
        return True

    def register_chain(owner, plane, table, start, expected, phys_bound,
                       size_bytes=None, sector_size=None):
        """Walk a chain, claim its verified prefix and record it."""
        result = walk_chain(table, start, expected=expected,
                            phys_bound=phys_bound)
        for kind, at, value in result['events']:
            event_owner = owner
            if kind in ('head_special', 'head_out_of_table',
                        'head_beyond_eof'):
                loc = {'plane': plane, 'sid': start}
                msg = '%s chain starts at %s' % (owner['label'],
                                                 _marker(value))
            else:
                loc = {'plane': plane, 'sid': at, 'next': value}
                msg = '%s: %s at sector %s -> %s' % (
                    owner['label'], kind, at if at is not None else start,
                    _marker(value))
            sev = SEV_ERROR
            if kind == 'chain_long':
                sev = SEV_WARN
            report.anomaly(sev, kind, loc, msg, owner=event_owner)

        prefix = result['prefix']
        stop_after = len(prefix)
        for ordinal, sid in enumerate(prefix):
            same = claim(plane, sid, owner, ordinal)
            if not same:
                stop_after = ordinal + 1
                if ordinal == len(prefix) - 1 and \
                        result['status'] == ST_OK:
                    result['status'] = ST_CROSS
                break
        prefix = prefix[:stop_after]
        result['prefix'] = prefix
        if prefix:
            report.chain_tails.add((plane, owner['kind'], owner['id'],
                                    prefix[-1]))
        chain = {
            'owner': owner,
            'plane': plane,
            'start': start,
            'start_marker': _marker(start) if _is_special(start)
                            else start,
            'declared_bytes': size_bytes,
            'sector_size': sector_size,
            'expected_sectors': expected,
            'verified_sectors': len(prefix),
            'prefix': prefix,
            'status': result['status'],
        }
        report.chains.append(chain)
        return chain

    # ---- 1) structural owners -------------------------------------------
    # DIFAT sectors
    for ordinal, sid in enumerate(difat_sids):
        owner = _owner('difat', ordinal,
                       'DIFAT sector #%d (FAT sid %d)' % (ordinal, sid))
        if sid < nb_sect:
            claim(PLANE_FAT, sid, owner, 0)

    # FAT sectors
    for ordinal, sid in enumerate(fat_sids):
        owner = _owner('fat', ordinal,
                       'FAT sector #%d (FAT sid %d)' % (ordinal, sid))
        if sid < nb_sect:
            claim(PLANE_FAT, sid, owner, 0)

    # ---- 2) directory chain ---------------------------------------------
    first_dir = hdr['first_dir_sector']
    dir_owner = _owner('directory', 0, 'Directory')
    dir_chain = None
    if _is_special(first_dir):
        report.anomaly(SEV_ERROR, 'directory_head_special',
                       {'plane': PLANE_FAT, 'sid': first_dir},
                       'first directory sector is %s'
                       % _marker(first_dir))
    elif first_dir >= table_bound or first_dir >= nb_sect:
        report.anomaly(SEV_ERROR, 'directory_head_oob',
                       {'plane': PLANE_FAT, 'sid': first_dir},
                       'first directory sector %d is out of bounds'
                       % first_dir)
    else:
        dir_chain = register_chain(dir_owner, PLANE_FAT, fat, first_dir,
                                   expected=None, phys_bound=nb_sect,
                                   sector_size=ss)

    # Read directory entries from the verified prefix
    direntries = []
    root = None
    if dir_chain is not None and dir_chain['prefix']:
        dir_data = b''.join(_read_sector(data, ss, sid)[0]
                            for sid in dir_chain['prefix'])
        direntries = parse_direntries(dir_data)
        if direntries and direntries[0]['type'] == STGTY_ROOT:
            root = direntries[0]
        else:
            report.anomaly(SEV_ERROR, 'root_entry_invalid',
                           {'plane': PLANE_FAT},
                           'directory entry #0 is not a Root entry')

    # ---- 3) MiniFAT chain ------------------------------------------------
    first_mf = hdr['first_minifat_sector']
    num_mf = hdr['num_minifat_sectors']
    minifat = []
    mf_owner = _owner('minifat', 0, 'MiniFAT')
    mf_prefix = []
    if num_mf == 0 and first_mf in (ENDOFCHAIN, FREESECT, NOSTREAM):
        pass  # no MiniFAT: normal
    elif _is_special(first_mf):
        if num_mf:
            report.anomaly(SEV_ERROR, 'minifat_head_special',
                           {'plane': PLANE_FAT, 'sid': first_mf},
                           'header declares %d MiniFAT sector(s) but first '
                           'is %s' % (num_mf, _marker(first_mf)))
    elif first_mf >= table_bound or first_mf >= nb_sect:
        report.anomaly(SEV_ERROR, 'minifat_head_oob',
                       {'plane': PLANE_FAT, 'sid': first_mf},
                       'first MiniFAT sector %d is out of bounds'
                       % first_mf)
    else:
        mf_chain = register_chain(mf_owner, PLANE_FAT, fat, first_mf,
                                  expected=num_mf if num_mf else None,
                                  phys_bound=nb_sect, sector_size=ss)
        mf_prefix = mf_chain['prefix']
    if mf_prefix:
        for sid in mf_prefix:
            minifat.extend(_u32_array(_read_sector(data, ss, sid)[0]))

    # ---- 4) root mini stream container ----------------------------------
    mini_bound = 0          # number of mini sectors physically available
    if root is not None and root['size'] > 0:
        root_owner = _owner('ministream_container', 0,
                            'Root Entry Mini Stream')
        expected_root = (root['size'] + ss - 1) // ss
        root_chain = register_chain(root_owner, PLANE_FAT, fat,
                                    root['start'], expected=expected_root,
                                    phys_bound=nb_sect,
                                    size_bytes=root['size'],
                                    sector_size=ss)
        container = b''.join(_read_sector(data, ss, sid)[0]
                             for sid in root_chain['prefix'])
        mini_bound = len(container) // mini_ss
    elif root is not None and root['start'] not in (ENDOFCHAIN, FREESECT):
        report.anomaly(SEV_WARN, 'root_start_without_size',
                       {'plane': PLANE_FAT, 'sid': root['start']},
                       'root entry is empty but starts at sector %d'
                       % root['start'])

    if minifat and mini_bound == 0:
        report.anomaly(SEV_WARN, 'minifat_without_ministream',
                       message='a MiniFAT is present but the root mini stream '
                               'is missing or empty')

    # ---- 5) directory tree reachability / orphan direntries --------------
    reachable = set()
    paths = {}
    if root is not None:
        paths[0] = ''
        # frame: (sid, path of this node, path of its parent storage)
        stack = [(0, '', None)]
        seen_tree = set()
        while stack:
            sid, node_path, parent_path = stack.pop()
            if sid in seen_tree:
                continue
            if sid < 0 or sid >= len(direntries):
                continue
            seen_tree.add(sid)
            reachable.add(sid)
            entry = direntries[sid]
            for field, target in (('child', entry['child']),
                                  ('right', entry['right']),
                                  ('left', entry['left'])):
                if target == NOSTREAM:
                    continue
                if target >= len(direntries):
                    report.anomaly(SEV_ERROR, 'direntry_tree_oob',
                                   {'direntry': sid, 'field': field,
                                    'target': target},
                                   'direntry %d (%s) %s points to %d, beyond '
                                   'directory (%d entries)'
                                   % (sid, entry['name'], field, target,
                                      len(direntries)))
                    continue
                if target in seen_tree:
                    report.anomaly(SEV_ERROR, 'direntry_tree_cycle',
                                   {'direntry': sid, 'field': field,
                                    'target': target},
                                   'directory tree edge %d -> %d (%s) closes '
                                   'a loop' % (sid, target, field))
                    continue
                name = direntries[target]['name']
                if field == 'child':
                    # a child lives inside this storage
                    target_path = node_path + '/' + name
                    if target not in paths:
                        paths[target] = target_path
                    stack.append((target, target_path, node_path))
                else:
                    # a red-black sibling shares the same parent storage
                    base = parent_path if parent_path is not None else ''
                    target_path = base + '/' + name
                    if target not in paths:
                        paths[target] = target_path
                    stack.append((target, target_path, base))

    for entry in direntries:
        sid = entry['sid']
        if entry['type'] == STGTY_EMPTY:
            continue
        if sid != 0 and sid not in reachable:
            report.anomaly(
                SEV_WARN, 'direntry_orphan',
                {'direntry': sid},
                'directory entry #%d (%r, type %s) is not reachable from the '
                'root storage tree' % (sid, entry['name'],
                                       ENTRY_TYPE_NAMES.get(entry['type'],
                                                            '?')))

    # ---- 6) streams and mini streams -------------------------------------
    stream_entries = [e for e in direntries
                      if e['type'] == STGTY_STREAM and e['sid'] != 0]
    for entry in sorted(stream_entries, key=lambda e: e['sid']):
        sid = entry['sid']
        path = paths.get(sid)
        if path is None:
            path = '/' + entry['name'] + ' (orphan direntry #%d)' % sid
        label = "stream '%s' (direntry #%d)" % (path, sid)
        owner = _owner('stream', sid, label)
        start = entry['start']
        size = entry['size']
        if size == 0:
            if start != ENDOFCHAIN:
                report.anomaly(SEV_WARN, 'empty_stream_start',
                               {'direntry': sid, 'plane': PLANE_FAT,
                                'sid': start},
                               '%s is empty but starts at %s'
                               % (label, _marker(start)),
                               owner=owner)
            continue
        if size < hdr['mini_cutoff']:
            # mini stream: chain lives in the MiniFAT, sectors of 64 bytes
            expected = (size + mini_ss - 1) // mini_ss
            if not minifat:
                report.anomaly(SEV_ERROR, 'ministream_no_minifat',
                               {'direntry': sid, 'mini_sid': start},
                               '%s needs a MiniFAT but none is available'
                               % label, owner=owner)
                continue
            chain = register_chain(owner, PLANE_MINI, minifat, start,
                                   expected=expected, phys_bound=mini_bound,
                                   size_bytes=size,
                                   sector_size=mini_ss)
            if mini_bound and start < mini_bound and \
                    chain['verified_sectors'] == 0:
                pass
        else:
            expected = (size + ss - 1) // ss
            register_chain(owner, PLANE_FAT, fat, start,
                           expected=expected, phys_bound=nb_sect,
                           size_bytes=size, sector_size=ss)

    # storage entries with a non-zero size are suspicious
    for entry in direntries:
        if entry['type'] == STGTY_STORAGE and entry['size'] != 0:
            report.anomaly(SEV_WARN, 'storage_with_size',
                           {'direntry': entry['sid']},
                           'storage %r declares size %d'
                           % (entry['name'], entry['size']))

    # ---- 7) FAT marker / ownership cross-check ---------------------------
    fat_sid_set = set(fat_sids)
    difat_sid_set = set(difat_sids)
    upper = max(table_bound, nb_sect)
    claimed_data = set()  # sectors claimed by non-structural data owners
    for claimed_sid, claims in report.big_claims.items():
        for owner_item, _o in claims:
            if owner_item['kind'] not in ('fat', 'difat', 'directory',
                                          'minifat', 'ministream_container'):
                claimed_data.add(claimed_sid)

    for i in range(upper):
        marker = fat[i] if i < table_bound else None
        claims = report.big_claims.get(i, [])
        owners_here = [o for o, _o in claims]
        claimed = bool(owners_here)
        claimed_by_data = i in claimed_data
        claimed_by_fat = any(o['kind'] == 'fat' for o in owners_here)
        claimed_by_difat = any(o['kind'] == 'difat' for o in owners_here)

        if i >= nb_sect:
            # entry exists in the FAT but the file does not contain it
            if marker not in (None, FREESECT) and not _is_special(marker):
                report.anomaly(SEV_WARN, 'fat_beyond_eof',
                               {'plane': PLANE_FAT, 'sid': i},
                               'FAT entry %d (%s) lies beyond the physical '
                               'file' % (i, _marker(marker)))
            continue
        if marker is None:
            report.anomaly(SEV_WARN, 'sector_beyond_fat',
                           {'plane': PLANE_FAT, 'sid': i},
                           'physical sector %d is not covered by the FAT'
                           % i)
            continue
        if i in fat_sid_set and marker != FATSECT:
            report.anomaly(SEV_WARN, 'marker_mismatch',
                           {'plane': PLANE_FAT, 'sid': i, 'value': marker},
                           'sector %d is listed as FAT in the DIFAT but its '
                           'FAT entry is %s' % (i, _marker(marker)))
        if i in difat_sid_set and marker != DIFSECT:
            report.anomaly(SEV_WARN, 'marker_mismatch',
                           {'plane': PLANE_FAT, 'sid': i, 'value': marker},
                           'sector %d is a DIFAT sector but its FAT entry is '
                           '%s' % (i, _marker(marker)))
        if marker == FATSECT and i not in fat_sid_set:
            report.anomaly(SEV_WARN, 'marker_mismatch',
                           {'plane': PLANE_FAT, 'sid': i, 'value': marker},
                           'FAT marks sector %d as FATSECT but the DIFAT does '
                           'not list it' % i)
        if marker == DIFSECT and i not in difat_sid_set:
            report.anomaly(SEV_WARN, 'marker_mismatch',
                           {'plane': PLANE_FAT, 'sid': i, 'value': marker},
                           'FAT marks sector %d as DIFSECT but no DIFAT chain '
                           'references it' % i)
        if marker == FREESECT and claimed:
            report.anomaly(SEV_ERROR, 'occupies_free_sector',
                           {'plane': PLANE_FAT, 'sid': i},
                           'sector %d is marked FREESECT but claimed by %s'
                           % (i, ', '.join(o['label']
                                           for o in owners_here)))
        if marker in (FATSECT, DIFSECT) and claimed_by_data:
            # the structural chain claims already generated a cross_occupied
            # anomaly; nothing else to add
            pass
        if _is_special(marker) and marker not in (FREESECT, ENDOFCHAIN,
                                                  FATSECT, DIFSECT):
            report.anomaly(SEV_WARN, 'invalid_marker',
                           {'plane': PLANE_FAT, 'sid': i, 'value': marker},
                           'FAT entry %d has unknown reserved value %s'
                           % (i, _marker(marker)))

    # ---- 8) orphan chains in the FAT -------------------------------------
    # candidates: physical, not claimed, not marked free/metadata
    candidates = set()
    for i in range(nb_sect):
        if i >= table_bound:
            continue
        marker = fat[i]
        if i in report.big_claims:
            continue
        if marker in (FREESECT, FATSECT, DIFSECT):
            continue
        # ENDOFCHAIN or a regular pointer: allocated data with no owner
        candidates.add(i)
    if candidates:
        successors = {}
        for i in candidates:
            nxt = fat[i]
            if nxt in candidates:
                successors[i] = nxt
        heads = [i for i in candidates
                 if not any(v == i for v in successors.values())]
        # pure cycles have no head: add the smallest remaining sid
        remaining = set(candidates)
        fragments = []
        for head in sorted(heads):
            frag = []
            cur = head
            while cur in remaining:
                remaining.discard(cur)
                frag.append(cur)
                cur = successors.get(cur)
                if cur is None or cur not in remaining:
                    break
            fragments.append(frag)
        while remaining:
            head = min(remaining)
            frag = []
            cur = head
            while cur in remaining:
                remaining.discard(cur)
                frag.append(cur)
                cur = successors.get(cur)
                if cur is None or cur not in remaining:
                    break
            fragments.append(frag)
        for frag in sorted(fragments, key=lambda f: f[0]):
            terminal = fat[frag[-1]] if fat[frag[-1]] not in (
                ENDOFCHAIN,) else ENDOFCHAIN
            report.anomaly(SEV_WARN, 'orphan_chain',
                           {'plane': PLANE_FAT, 'head': frag[0],
                            'sectors': frag,
                            'terminal': _marker(fat[frag[-1]])},
                           'orphan FAT chain of %d sector(s) starting at %d, '
                           'unreachable from the directory'
                           % (len(frag), frag[0]))

    # ---- 9) MiniFAT markers and orphan mini chains -----------------------
    if minifat:
        for i in range(len(minifat)):
            marker = minifat[i]
            claims = report.mini_claims.get(i, [])
            owners_here = [o for o, _o in claims]
            beyond = i >= mini_bound
            if marker in (FATSECT, DIFSECT) or (
                    _is_special(marker) and marker not in
                    (FREESECT, ENDOFCHAIN)):
                report.anomaly(SEV_WARN, 'invalid_marker',
                               {'plane': PLANE_MINI, 'sid': i,
                                'value': marker},
                               'MiniFAT entry %d has invalid value %s'
                               % (i, _marker(marker)))
            if marker == FREESECT and owners_here:
                report.anomaly(SEV_ERROR, 'occupies_free_sector',
                               {'plane': PLANE_MINI, 'sid': i},
                               'mini sector %d is marked FREESECT but claimed '
                               'by %s' % (i, ', '.join(o['label']
                                                       for o in owners_here)))
            if beyond:
                if marker != FREESECT or owners_here:
                    # walking chains already reported reachability faults;
                    # only flag dangling table entries
                    if not owners_here and not _is_special(marker):
                        report.anomaly(SEV_WARN, 'minifat_beyond_ministream',
                                       {'plane': PLANE_MINI, 'sid': i},
                                       'MiniFAT entry %d (%s) lies beyond the '
                                       'root mini stream (%d mini sectors)'
                                       % (i, _marker(marker), mini_bound))
                continue
        # mini orphans
        mini_candidates = set()
        for i in range(min(mini_bound, len(minifat))):
            if i in report.mini_claims:
                continue
            marker = minifat[i]
            if marker in (FREESECT, FATSECT, DIFSECT):
                continue
            mini_candidates.add(i)
        mini_succ = dict((i, minifat[i]) for i in mini_candidates
                         if minifat[i] in mini_candidates)
        mini_heads = [i for i in mini_candidates
                      if not any(v == i for v in mini_succ.values())]
        remaining = set(mini_candidates)
        fragments = []
        for head in sorted(mini_heads):
            frag = []
            cur = head
            while cur in remaining:
                remaining.discard(cur)
                frag.append(cur)
                cur = mini_succ.get(cur)
                if cur is None or cur not in remaining:
                    break
            fragments.append(frag)
        while remaining:
            head = min(remaining)
            frag = []
            cur = head
            while cur in remaining:
                remaining.discard(cur)
                frag.append(cur)
                cur = mini_succ.get(cur)
                if cur is None or cur not in remaining:
                    break
            fragments.append(frag)
        for frag in sorted(fragments, key=lambda f: f[0]):
            report.anomaly(SEV_WARN, 'orphan_chain',
                           {'plane': PLANE_MINI, 'head': frag[0],
                            'sectors': frag,
                            'terminal': _marker(minifat[frag[-1]])},
                           'orphan mini chain of %d sector(s) starting at %d'
                           % (len(frag), frag[0]))

    # ---- 10) finalize sector maps ----------------------------------------
    for i in range(max(table_bound, nb_sect)):
        marker = fat[i] if i < table_bound else None
        claims = [{'owner': o, 'ordinal': o_rd}
                  for o, o_rd in report.big_claims.get(i, [])]
        report.big_sector_map.append({
            'sid': i,
            'offset': ss * (i + 1),
            'fat': _marker(marker) if marker is not None else 'OUT_OF_FAT',
            'physical': i < nb_sect,
            'claims': claims,
        })
    for i in range(max(len(minifat), mini_bound)):
        marker = minifat[i] if i < len(minifat) else None
        claims = [{'owner': o, 'ordinal': o_rd}
                  for o, o_rd in report.mini_claims.get(i, [])]
        report.mini_sector_map.append({
            'sid': i,
            'offset': i * mini_ss,
            'minifat': _marker(marker) if marker is not None
                       else 'OUT_OF_MINIFAT',
            'physical': i < mini_bound,
            'claims': claims,
        })

    return report


# === TEXT REPORT ============================================================

STATUS_COLORS = {
    ST_OK: 'green',
    ST_TRUNCATED: 'red',
    ST_CYCLE: 'red',
    ST_OOB_TABLE: 'red',
    ST_OOB_FILE: 'red',
    ST_HEAD_OOB: 'red',
    ST_HEAD_SPECIAL: 'red',
    ST_RESERVED: 'red',
    ST_FREE_TARGET: 'red',
    ST_CROSS: 'red',
    ST_LONG: 'yellow',
    ST_UNBOUNDED: 'red',
}

SEVERITY_COLORS = {
    SEV_ERROR: 'red',
    SEV_WARN: 'yellow',
    SEV_INFO: None,
}


def print_report(report, show_map=False, show_mini_map=False):
    if report.fatal:
        print('FATAL: cannot analyse %s: %s' % (report.filename,
                                                report.fatal))
        return
    h = report.header
    print('FILE: %s' % report.filename)
    print('  sector size: %d bytes | %d physical sectors | FAT entries: %d '
          '| file size: %d bytes'
          % (h['sector_size'], h['nb_sect'], h['fat_entries'],
             h['file_size']))
    print('  first dir sector: %s | MiniFAT: %s sector(s) @ %s | DIFAT: %d '
          'sector(s)'
          % (_marker(h['first_dir_sector'])
             if _is_special(h['first_dir_sector'])
             else h['first_dir_sector'],
             h['num_minifat_sectors'],
             _marker(h['first_minifat_sector'])
             if _is_special(h['first_minifat_sector'])
             else h['first_minifat_sector'],
             h['num_difat_sectors']))
    print('')

    print('CHAINS (verified prefixes):')
    t = tablestream.TableStream(
        column_width=[44, 8, 10, 8, 8, 18],
        header_row=('Owner', 'Plane', 'Start', 'Expect', 'Prefix', 'Status'),
        style=tablestream.TableStyleSlim)
    for chain in report.chains:
        start = chain['start_marker']
        t.write_row(
            (chain['owner']['label'][:44], chain['plane'], str(start),
             str(chain['expected_sectors']),
             str(chain['verified_sectors']), chain['status']),
            colors=(None, None, None, None, None,
                    STATUS_COLORS.get(chain['status'])))
    t.close()
    print('')

    if report.anomalies:
        print('ANOMALIES:')
        t = tablestream.TableStream(
            column_width=[6, 22, 22, 60],
            header_row=('Sev', 'Kind', 'Location', 'Detail'),
            style=tablestream.TableStyleSlim)
        for a in report.anomalies:
            loc = a['location']
            if 'plane' in loc:
                loc_txt = '%s:%s' % (loc['plane'],
                                     loc.get('sid', loc.get('head', '?')))
            elif 'direntry' in loc:
                loc_txt = 'dir#%s' % loc['direntry']
            else:
                loc_txt = ''
            t.write_row(
                (a['severity'], a['kind'], loc_txt, a['message'][:60]),
                colors=(SEVERITY_COLORS.get(a['severity']), None, None, None))
        t.close()
    else:
        print('No anomalies detected: every allocated sector has exactly one '
              'reachable owner.')
    print('')

    if show_map:
        print('BIG SECTOR OWNERSHIP MAP:')
        t = tablestream.TableStream(
            column_width=[8, 10, 12, 46],
            header_row=('Sector', 'Offset', 'FAT entry', 'Owner(s)'),
            style=tablestream.TableStyleSlim)
        skipped = 0
        for row in report.big_sector_map:
            owners = ', '.join(c['owner']['label'] for c in row['claims'])
            if owners:
                pass
            elif row['fat'] == 'FREESECT':
                owners = 'free'
            elif row['fat'] in ('FATSECT', 'DIFSECT'):
                owners = '-'
            else:
                owners = 'ORPHAN (unclaimed)'
            if not row['physical'] and not row['claims'] and \
                    row['fat'] == 'FREESECT':
                skipped += 1
                continue
            color = None
            if len(row['claims']) > 1:
                color = 'red'
            elif row['fat'] == 'FREESECT' and row['claims']:
                color = 'red'
            elif owners.startswith('ORPHAN'):
                color = 'yellow'
            t.write_row((str(row['sid']), '%08X' % row['offset'],
                         row['fat'], owners[:46]),
                        colors=(color, color, color, color))
        t.close()
        if skipped:
            print('  (%d non-physical FREESECT entries beyond end of file '
                  'not shown; use --json for the full table)' % skipped)
        print('')

    if show_mini_map and report.mini_sector_map:
        print('MINI SECTOR OWNERSHIP MAP:')
        t = tablestream.TableStream(
            column_width=[8, 10, 12, 46],
            header_row=('MiniSect', 'Offset', 'MiniFAT', 'Owner(s)'),
            style=tablestream.TableStyleSlim)
        skipped = 0
        for row in report.mini_sector_map:
            owners = ', '.join(c['owner']['label'] for c in row['claims'])
            if owners:
                pass
            elif row['minifat'] == 'FREESECT':
                owners = 'free'
            else:
                owners = 'ORPHAN (unclaimed)'
            if not row['physical'] and not row['claims'] and \
                    row['minifat'] == 'FREESECT':
                skipped += 1
                continue
            color = 'red' if len(row['claims']) > 1 else None
            if owners.startswith('ORPHAN'):
                color = 'yellow'
            t.write_row((str(row['sid']), '%06X' % row['offset'],
                         row['minifat'], owners[:46]),
                        colors=(color, color, color, color))
        t.close()
        if skipped:
            print('  (%d non-physical FREESECT MiniFAT entries beyond the '
                  'mini stream not shown; use --json for the full table)'
                  % skipped)
        print('')

    s = report.summary()
    print('SUMMARY: %d chain(s), %d big sector(s), %d mini sector(s) | '
          'errors: %d, warnings: %d, infos: %d'
          % (s['chains'], s['big_sectors'], s['mini_sectors'],
             s['errors'], s['warnings'], s['infos']))


# === MAIN ===================================================================

def main():
    usage = 'usage: oleowner [options] <filename> [filename2 ...]'
    parser = optparse.OptionParser(usage=usage)
    parser.add_option('-r', action='store_true', dest='recursive',
                      help='find files recursively in subdirectories.')
    parser.add_option('-z', '--zip', dest='zip_password', type='str',
                      default=None,
                      help='if the file is a zip archive, open all files '
                           'from it, using the provided password')
    parser.add_option('-f', '--zipfname', dest='zip_fname', type='str',
                      default='*',
                      help='file(s) to open within a zip archive '
                           '(default: *)')
    parser.add_option('--map', action='store_true', dest='show_map',
                      help='display the full big-sector ownership map')
    parser.add_option('--mini-map', action='store_true', dest='show_mini_map',
                      help='display the full mini-sector ownership map')
    parser.add_option('--json', action='store_true', dest='json_output',
                      help='emit the full report as deterministic JSON')

    (options, args) = parser.parse_args()
    if len(args) == 0:
        print(BANNER)
        print(__doc__)
        parser.print_help()
        sys.exit()

    if not options.json_output:
        print(BANNER)
    reports = []
    for container, filename, data in xglob.iter_files(
            args, recursive=options.recursive,
            zip_password=options.zip_password, zip_fname=options.zip_fname):
        if container and filename.endswith('/'):
            continue
        full_name = '%s in %s' % (filename, container) if container \
            else filename
        if data is None:
            with open(filename, 'rb') as fp:
                data = fp.read()
        report = analyze(data, filename=full_name)
        reports.append(report)
        if options.json_output:
            continue
        print('-' * 79)
        print_report(report, show_map=options.show_map,
                     show_mini_map=options.show_mini_map)

    if options.json_output:
        if len(reports) == 1:
            print(json.dumps(reports[0].to_dict(), indent=2, sort_keys=True))
        else:
            print(json.dumps([r.to_dict() for r in reports], indent=2,
                             sort_keys=True))

    # exit status: 1 if any file had fatal errors or ERROR-level anomalies
    bad = any(r.fatal or
              any(a['severity'] == SEV_ERROR for a in r.anomalies)
              for r in reports)
    if bad:
        sys.exit(1)


if __name__ == '__main__':
    main()
