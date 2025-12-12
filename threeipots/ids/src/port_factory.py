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
        try:
            port = trame['tcp.port'].iloc[0]
        except Exception as e:
            port = trame['udp.port'].iloc[0]
        
        # TODO port

        processor = self.port_map.get(port)
        if processor:
            return processor
        else:
            try:
                raise ValueError(f"Unknown port {port}")
            except ValueError as e:
                pass
