#!/usr/bin/env python3

import sys
from datetime import datetime
from datetime import timedelta
from datetime import timezone

from pprint import pprint
from influxdb import InfluxDBClient

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

version = None
commit = None

allocations = {}
stats = {}

ot = datetime.fromtimestamp(0)

tzlocal = datetime.now(timezone.utc).astimezone().tzinfo

client = InfluxDBClient("<FILLME>", 8086,
                        '<FILLME>', '<FILLME>',
                        database='<FILLME>',
                        ssl=True)

for line in sys.stdin:
    unpacked = line.strip().split()
    if len(unpacked) == 0:
        # empty line
        continue

    op = unpacked[0]

    try:
        t = datetime.strptime(f"{unpacked[0]} {unpacked[1]}",
                              "%d-%b-%Y %H:%M:%S.%f")

        op = "time"
    except ValueError:
        if op != 'add' and op != 'del':
            continue

    if op == "time":

        tdelta = t - ot
        if tdelta > timedelta(seconds=60):
            ot = t
            op = "dump"

        if len(unpacked) < 5:
            continue

        if unpacked[2] == "starting" and unpacked[3] == "BIND":
            version = unpacked[4]

            (id, commit) = unpacked[-1].strip("<>").split(":")
            if id != "id":
                commit = None

    if op == "dump":
        time_str = t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S%Z")
        points = [
            {
                "measurement": f'BIND-{version}',
                "tags": {
                    "version": version,
                },
                "time": time_str,
                "fields": {}
            }
        ]

        write = False

        if commit is not None:
            points[0]["tags"]["commit"] = commit

        for key in stats:
            size = stats[key]['size']
            points[0]["fields"][key] = size
            write = True

        pprint(points)

        if write:
            assert client.write_points(points,
                                       time_precision='s',
                                       retention_policy='bind9')

    if op != 'add' and op != 'del':
        continue

    ptr = unpacked[1]
    size = int(unpacked[3])
    file = unpacked[5]
    line = int(unpacked[7])
    mctx = unpacked[9]

    # add 0x7fc9f2812000 size 8192 file lib.c line 49 mctx 0x7fc9ff409000
    if op == 'add':
        assert ptr not in allocations

        allocations[ptr] = (int(size), file, line, mctx)
        key = f'{file}-{line}'
        if key in stats:
            stats[key]['size'] += size
            stats[key]['allocations'].append(ptr)
        else:
            stats[key] = {}
            stats[key]['size'] = size
            stats[key]['allocations'] = [ptr]

    # del 0x7fc9f2812000 size 8192 file lib.c line 49 mctx 0x7fc9ff409000
    if op == 'del':
        assert ptr in allocations
        assert size == allocations[ptr][0]
        assert mctx == allocations[ptr][3]

        (size, file, line, mctx) = allocations[ptr]

        del allocations[ptr]

        key = f'{file}-{line}'
        assert key in stats

        stats[key]['size'] -= size
        stats[key]['allocations'].remove(ptr)

        assert stats[key]['size'] >= 0

client.close()
