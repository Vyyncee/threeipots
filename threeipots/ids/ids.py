from src.port_factory import PortFactory
import pyshark
import queue
import threading
import pandas as pd
from threeipots.utils.protocol import Protocol
from threeipots.utils.packet_utils import PacketUtils


# Construire le filtre
# Récupérer tous les ports
all_ports = [str(port) for proto in Protocol for port in proto.value]
PORT_FILTER = " or ".join(f"tcp port {port}" for port in all_ports)

packet_queue = queue.Queue()

def packet_worker():
    portFactory = PortFactory()

    while True:
        pkt = packet_queue.get()

        if pkt is None:
            continue

        dict = PacketUtils.toDict(pkt)

        trame = pd.DataFrame([dict])

        processor = portFactory.create_processor(trame)

        if processor is None:
            continue

        # Prédit et Sauvegarde
        processor.predict(trame)

        packet_queue.task_done()

threading.Thread(target=packet_worker, daemon=True).start()

capture = pyshark.LiveCapture(
    interface='eno1',
    bpf_filter=PORT_FILTER
)

for pkt in capture.sniff_continuously():
    packet_queue.put(pkt)