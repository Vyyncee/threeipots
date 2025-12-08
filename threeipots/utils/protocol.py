from enum import Enum

class Protocol(Enum):
    SSH_TELNET = [22, 23]
    HTTP = [80]
    RAW = [9100]
    SMTP = [25, 587]