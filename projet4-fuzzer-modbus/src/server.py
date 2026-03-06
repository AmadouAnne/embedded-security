#!/usr/bin/env python3
from pymodbus.server import StartTcpServer
from pymodbus.datastore import ModbusDeviceContext, ModbusServerContext
from pymodbus.datastore import ModbusSequentialDataBlock

def run_server():
    store = ModbusDeviceContext(
        co=ModbusSequentialDataBlock(0, [1]*100),
        di=ModbusSequentialDataBlock(0, [1]*100),
        hr=ModbusSequentialDataBlock(0, [42]*100),
        ir=ModbusSequentialDataBlock(0, [99]*100),
    )
    context = ModbusServerContext(devices=store, single=True)
    print("[+] Serveur Modbus TCP sur 127.0.0.1:5020")
    print("[+] 100 holding registers -- valeur initiale : 42")
    print("[+] CTRL+C pour arreter")
    StartTcpServer(context=context, address=("127.0.0.1", 5020))

run_server()
