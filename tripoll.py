#!/usr/bin/env python
"""
Usage: tripoll.py --config=config [--debug]
"""

from docopt import docopt
import logging
import yaml
import sys
import time
import threading
import re
from datetime import datetime
from pysnmp.hlapi import *
from pysnmp.entity.rfc3413.oneliner import cmdgen
from influxdb import InfluxDBClient

LOG_FORMAT = '[%(levelname)s] - %(asctime)s (%(threadName)-10s) %(message)s'
debug = False

logger = logging.getLogger('tripoll')
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter(LOG_FORMAT)
ch.setFormatter(formatter)
logger.addHandler(ch)


def debug_log(msg):
    if debug:
        logger.debug(msg)


def load_config(config_file):
    try:
        with open(config_file, 'r') as f:
            return yaml.load(f)
    except Exception as e:
        print('Failed to read config {}: {}'.format(config_file, e))
        sys.exit(1)


def build_json(measurement, hostname, interface, timestamp, value):
    json_body = [
        {
            "measurement": "{}".format(measurement),
            "tags": {
                "host": "{}".format(hostname),
                "interface": "{}".format(interface)
            },
            "time": "{}".format(timestamp),
            "fields": {
                "value": value
            }
        }
    ]
    return json_body


def poll(what, interface, snmp_engine, community_data, transport_target):
    err_indication, err_status, err_index, var_binds = next(
        getCmd(snmp_engine,
               community_data,
               transport_target,
               ContextData(),
               ObjectType(ObjectIdentity('IF-MIB', what, interface)))
    )

    if err_indication:
        logger.warning("Poll failed: " + str(err_indication))
        return err_indication, 0
    elif err_status:
        print('%s at %s' % (
            err_status.prettyPrint(),
            err_index and var_binds[int(err_index) - 1][0] or '?'))
    else:
        return 'success', long(var_binds[0][1])


def get_interface_id_from_mib(oid):
    return oid.split('.')[-1]


def get_current_time():
    return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')


def get_interface_ids(config):
    for host in config['hosts']:
        logger.info('getting interface ids for %s' % host)
        cmd_gen = cmdgen.CommandGenerator()
        interfaces = []
        err_indication, err_status, err_index, varbindtable = cmd_gen.nextCmd(
            cmdgen.CommunityData(config['snmp']['community']),
            cmdgen.UdpTransportTarget((host, config['snmp']['port'])),
            '1.3.6.1.2.1.2.2.1.2'
        )

        if err_indication:
            logger.warning(err_indication)
        else:
            if err_status:
                print('%s at %s' % (
                    err_status.prettyPrint(),
                    err_index and varbindtable[-1][int(err_index)-1] or '?'))
            else:
                for varBindTableRow in varbindtable:
                    for name, val in varBindTableRow:
                        for interface in config['hosts'][host]['interfaces']:
                            regex = re.compile("%s$" % interface)
                            m = re.search(regex, str(val.prettyPrint()))
                            if m:
                                interface_id = get_interface_id_from_mib(str(name))
                                interface_data = (interface, interface_id)
                                interfaces.append(interface_data)
                                break

        config['hosts'][host]['interfaces'] = interfaces
    return config


def worker(cfg, host):
    influx = InfluxDBClient(cfg['influx']['hostname'],
                            cfg['influx']['port'],
                            cfg['influx']['username'],
                            cfg['influx']['password'],
                            cfg['influx']['database'])

    snmp_engine = SnmpEngine()
    community_data = CommunityData(cfg['snmp']['community'], mpModel=1)
    transport_target = UdpTransportTarget((host, cfg['snmp']['port']))

    while True:
        for interface in cfg['hosts'][host]['interfaces']:
            for what in ['ifHCInOctets', 'ifHCOutOctets']:
                status, value = poll(what,
                                     interface[1],
                                     snmp_engine,
                                     community_data,
                                     transport_target)
                if status == 'success':
                    current_time = get_current_time()
                    json_data = build_json(what,
                                           host,
                                           interface[0],
                                           current_time,
                                           value)
                    debug_log(json_data)
                    influx.write_points(json_data)
        time.sleep(10)


def main():
    args = docopt(__doc__)

    logger.info('tripoll starting')

    config = load_config(args['--config'])

    global debug
    if args['--debug']:
        debug = True

    cfg = get_interface_ids(config)

    threads = []
    for host in cfg['hosts']:
        thread_name = 'poller-%s' % host
        t = threading.Thread(name=thread_name,
                             target=worker,
                             args=(cfg, host,))
        t.daemon = True
        threads.append(t)
        t.start()

    while True:
        logger.info('tripoll is alive')
        time.sleep(60)


if __name__ == '__main__':
    main()
