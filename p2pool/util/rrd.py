from __future__ import absolute_import
from math import ceil
import rrdtool
import re
import os
import pprint

class MultiScaleRRDGraph(object):
    def sanitizeName(self, key):
        key = re.sub(r'\W', r'_', key) # Replace symbols and whitespace
        return key
    
    def __init__(self, name, datadir_path, mType='GAUGE', heartbeat=None, lowerBound=0, upperBound='U', resolution=720, timestep=5):
        self.dataDir = datadir_path;
        self.timestep = timestep # in seconds
        self.resolution = resolution
        self.heartbeat = heartbeat or timestep + 1
        self.name = self.sanitizeName(name)
        self.fileName = os.path.join(self.dataDir, self.name + '.rrd')        

        steps_per_hour = (60*60)/(self.timestep*self.resolution)
        self.periodConfigs = [
            ('last_hour', 
                'RRA:AVERAGE:0.5:%i:%i' % (ceil(steps_per_hour), self.resolution),
                'AVERAGE:start=end-1h'), # 1h
            ('last_day', 
                'RRA:AVERAGE:0.5:%i:%i' % (ceil(steps_per_hour*24), self.resolution),
                'AVERAGE:start=end-24h'), # 1d, we specify the time in hours because days aren't always 24 hours long...
            ('last_week', 
                'RRA:AVERAGE:0.5:%i:%i' % (ceil(steps_per_hour*24*7), self.resolution),
                'AVERAGE:start=end-168h'), # 7d
            ('last_month', 
                'RRA:AVERAGE:0.5:%i:%i' % (ceil(steps_per_hour*24*31), self.resolution),
                'AVERAGE:start=end-744h'), # 31d
            ('last_year', 
                'RRA:AVERAGE:0.5:%i:%i' % (ceil(steps_per_hour*24*366), self.resolution),
                'AVERAGE:start=end-8784h'), # 366d
        ]

        # save a period name => xport config mapping
        self.periods = dict([(_[0], _[2]) for _ in self.periodConfigs])
        
        if not os.path.exists(self.fileName):
            # Use timespans from the second column of rras, above
            rras = [_[1] for _ in self.periodConfigs]

            # Just one data source per file
            data_sources = ['DS:%s:%s:%s:%s:%s' % (self.name, mType, self.heartbeat, str(lowerBound), str(upperBound))]
            pprint.pprint(data_sources)
            
            rrdtool.create(
                self.fileName,
                '--step', str(self.timestep),
                data_sources,
                rras
            )

    def update(self, sample):
        rrdtool.update(self.fileName, 'N:%s' % sample)
        print(self.fileName, 'N:%s' % sample)
    
    def getData(self, period):
        assert period in self.periods
        r = rrdtool.xport(
            'DEF:x=%s:%s:%s' % (self.fileName, self.name, self.periods[period]),
            'XPORT:x:'
        )
        return r
