from enum import Enum


class TlvTypes(Enum):
    NIL = 0x00
    ERR = 0x01
    STR = 0x02
    INT64 = 0x03
    ARR = 0x04


class Commands(Enum):
    PING = 0
    SET = 1
    GET = 2
    DELETE = 3
    TTL = 4
    EXPIRE = 5
    INFO = 6
