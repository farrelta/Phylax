"""Fictional support-site simulator. Only Compose-internal simulated PLC is used."""
import os
import socket
import sys
import time

if os.environ.get('PHYLAX_LAB_ONLY')!='1':raise SystemExit('Run this driver only in the documented isolated lab')
role=sys.argv[1] if len(sys.argv)>1 else ''
if role=='it':
    from http.server import HTTPServer,SimpleHTTPRequestHandler
    HTTPServer(('0.0.0.0',8080),SimpleHTTPRequestHandler).serve_forever()
elif role=='plc':
    from pymodbus.datastore import ModbusDeviceContext,ModbusServerContext,ModbusSequentialDataBlock
    from pymodbus.server import StartTcpServer
    device=ModbusDeviceContext(hr=ModbusSequentialDataBlock(0,[0]*100))
    StartTcpServer(context=ModbusServerContext(devices=device,single=True),address=('0.0.0.0',502))
elif role in {'reader','rogue'}:
    from pymodbus.client import ModbusTcpClient
    # No target argument: only the fixed simulator address on the internal lab.
    if socket.gethostbyname('plc')!='172.30.77.10':raise SystemExit('PLC hostname is not the isolated lab endpoint')
    while True:
        client=ModbusTcpClient('plc',port=502,timeout=2,retries=0)
        try:
            if client.connect():
                response=client.write_register(0,1,device_id=1) if role=='rogue' else client.read_holding_registers(0,count=1,device_id=1)
                print(f'SYNTHETIC {role}: {response}',flush=True)
                if role=='rogue':break
        finally:client.close()
        time.sleep(2)
else:raise SystemExit('Use it, plc, reader, or rogue role')
