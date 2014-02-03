#!/usr/bin/env python

import util.rrd
import time
import pprint

x = util.rrd.MultiScaleRRDGraph(
        name="test",
        datadir_path="./rrds",
        )

for i in range(1,1000):
    x.update(i)
    pprint.pprint(x.getData('last_hour'))
    time.sleep(5)
