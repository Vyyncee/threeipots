from http_processor import HttpProcessor
from ssh_telnet_processor import SshTelnetProcessor
from smtp_processor import SmtpProcessor
from ipp_raw_lpd_processor import IppRawLpdProcessor

class PortFactory:

    def __init__(self):
        self.port_map = {
            80: HttpProcessor,
            22: SshTelnetProcessor,
            23: SshTelnetProcessor,
            25: SmtpProcessor, 
            587: SmtpProcessor,
            9100: IppRawLpdProcessor
        }
    
    def create_processor(self, trame):
        port = 0
        # TODO recuperation du port
        processor = self.port_map.get(port)
        if processor:
            return processor()
        else:
            raise ValueError(f"Unknown port {port}")
