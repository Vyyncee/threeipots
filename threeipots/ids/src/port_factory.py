from .http_processor import HttpProcessor
from .ssh_telnet_processor import SshTelnetProcessor
from .smtp_processor import SmtpProcessor
from .raw_processor import RawProcessor

class PortFactory:

    def __init__(self):
        httpProcessor = HttpProcessor()
        sshTelnetProcessor = SshTelnetProcessor()
        smtpProcessor = SmtpProcessor()
        rawProcessor = RawProcessor()

        self.port_map = {
            '80': httpProcessor,
            '22': sshTelnetProcessor,
            '23': sshTelnetProcessor,
            '25': smtpProcessor, 
            '587': smtpProcessor,
            '9100': rawProcessor
        }
    
    def create_processor(self, trame):
        ports = []

        if 'tcp.srcport' in trame.columns:
            ports.append(trame['tcp.srcport'].iloc[0])
        if 'tcp.dstport' in trame.columns:
            ports.append(trame['tcp.dstport'].iloc[0])

        if 'udp.srcport' in trame.columns:
            ports.append(trame['udp.srcport'].iloc[0])
        if 'udp.dstport' in trame.columns:
            ports.append(trame['udp.dstport'].iloc[0])

        processor = None
        for p in ports:
            if p in self.port_map:
                processor = self.port_map[p]
                break

        if processor:
            return processor
        else:
            try:
                raise ValueError(f"Unknown port {ports}")
            except ValueError as e:
                pass
