from http_processor import HttpProcessor
from ssh_telnet_processor import SshTelnetProcessor
from smtp_processor import SmtpProcessor
from ipp_raw_lpd_processor import IppRawLpdProcessor

class PortFactory:

    def __init__(self):
        httpProcessor = HttpProcessor()
        sshTelnetProcessor = SshTelnetProcessor()
        smtpProcessor = SmtpProcessor()
        ippRawLpdProcessor = IppRawLpdProcessor()

        self.port_map = {
            80: httpProcessor,
            22: sshTelnetProcessor,
            23: sshTelnetProcessor,
            25: smtpProcessor, 
            587: smtpProcessor,
            9100: ippRawLpdProcessor
        }
    
    def create_processor(self, trame):
        port = 0
        # TODO recuperation du port
        processor = self.port_map.get(port)
        if processor:
            return processor
        else:
            raise ValueError(f"Unknown port {port}")
