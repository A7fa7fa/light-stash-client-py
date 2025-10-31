import socket
import ssl
from typing import Any, Optional, Type

from .protocol import Commands, TlvTypes
from .exception import LightStashError


class TlvParser:
    def encode_tlv(self, tlv_type: TlvTypes, value: bytes) -> bytes:
        if tlv_type == TlvTypes.NIL:
            return tlv_type.value.to_bytes(length=1, byteorder="big", signed=False)

        if tlv_type == TlvTypes.ERR:
            raise LightStashError("Error not implemented")

        if tlv_type == TlvTypes.STR:
            tlv = b""
            tlv += tlv_type.value.to_bytes(length=1, byteorder="big", signed=False)
            tlv += len(value).to_bytes(length=4, byteorder="big", signed=False)
            tlv += value
            return tlv

        if tlv_type == TlvTypes.INT64:
            assert len(value) == 8 and "int should by 64bit"
            tlv = b""
            tlv += tlv_type.value.to_bytes(length=1, byteorder="big", signed=False)
            tlv += value
            return tlv

        if tlv_type == TlvTypes.ARR:
            raise LightStashError("Arr not implemented")

        raise LightStashError("unkown tlv type")

    def decode_tlv(
        self, data: bytes, offset: int = 0
    ) -> tuple[TlvTypes, None | str | int, int]:
        # TODO bytearray buffer?
        if len(data) == 0:
            raise LightStashError("Empty bytes can not be decoded to tlv")

        tlv_type = int.from_bytes(
            bytes=data[offset : offset + 1], byteorder="big", signed=False
        )

        if tlv_type == 0:
            return TlvTypes.NIL, None, offset + 1

        if tlv_type == 1:
            error_code = int.from_bytes(
                bytes=data[offset + 1 : offset + 5], byteorder="big", signed=False
            )
            payload_size = int.from_bytes(
                bytes=data[offset + 5 : offset + 5 + 4], byteorder="big", signed=False
            )
            payload = data[offset + 5 + 4 : offset + 5 + 4 + payload_size].decode(
                encoding="utf-8"
            )

            return (
                TlvTypes.ERR,
                f"{error_code} - {payload}",
                offset + 5 + 4 + payload_size,
            )

        if tlv_type == 2:
            payload_size = int.from_bytes(
                bytes=data[offset + 1 : offset + 5], byteorder="big", signed=False
            )
            payload = data[offset + 5 : offset + 5 + payload_size].decode(
                encoding="utf-8"
            )
            return TlvTypes.STR, payload, offset + 5 + payload_size

        if tlv_type == 3:
            payload = int.from_bytes(
                bytes=data[offset + 1 : offset + 9], byteorder="big", signed=True
            )
            return TlvTypes.INT64, payload, offset + 9

        if tlv_type == 4:
            raise LightStashError("Arr not implemented")

        raise LightStashError("Not implemented")


# TODO response object and error handling


class LightStashClient:
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 1234,
        use_tls: bool = False,
        cafile: str | None = None,
        sock_timeout: float = 2.0,
    ):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.cafile = cafile
        self.timeout = sock_timeout
        self.sock: None | socket.socket | ssl.SSLSocket = None
        self.tlv_parser = TlvParser()

    def connect(self) -> None:
        if self.sock:
            return

        raw_sock = socket.create_connection(
            (self.host, self.port), timeout=self.timeout
        )

        if self.use_tls:
            ctx = ssl.create_default_context(
                ssl.Purpose.SERVER_AUTH, cafile=self.cafile
            )
            self.sock = ctx.wrap_socket(raw_sock, server_hostname=self.host)
        else:
            self.sock = raw_sock

    def disconnect(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def _send_tlv(
        self, request_command: Commands, items: list[tuple[TlvTypes, bytes]]
    ) -> None:
        # TODO use bytearray as buffer instead of cocat bytes
        encoded_tlvs = b"".join(self.tlv_parser.encode_tlv(t, v) for t, v in items)
        encoded_request_command = request_command.value.to_bytes(
            length=4, byteorder="big", signed=False
        )
        package_size = (len(encoded_tlvs) + len(encoded_request_command)).to_bytes(
            length=4, byteorder="big", signed=False
        )
        payload = b""
        payload += package_size
        payload += encoded_request_command
        payload += encoded_tlvs
        self._sendall(payload)

    def _read_from_socket(self, num_bytes: int) -> bytes:
        if self.sock is None:
            raise LightStashError("Sock dead")
        data = self.sock.recv(num_bytes)
        return data

    def _recv_response_header(self) -> tuple[int, int]:
        header_raw = self._read_from_socket(8)
        size = int.from_bytes(bytes=header_raw[0:4], byteorder="big", signed=False)
        status = int.from_bytes(bytes=header_raw[4:8], byteorder="big", signed=False)
        return size, status

    def _recv_tlv_response(self) -> list[tuple[TlvTypes, Any]]:
        size, status = self._recv_response_header()
        if status != 1:
            print(f"Error response - status not ok {status}")

        response_raw = self._read_from_socket(size)

        result: list[tuple[TlvTypes, Any]] = []
        offset = 0
        while offset < len(response_raw):
            t, v, offset = self.tlv_parser.decode_tlv(response_raw, offset)
            result.append((t, v))
        print(result)
        return result

    def _sendall(self, data: bytes) -> None:
        if self.sock is None:
            raise LightStashError("sock is dead -  could not send")
        total_sent = 0
        while total_sent < len(data):
            sent = self.sock.send(data[total_sent:])
            if sent == 0:
                raise LightStashError("Socket connection broken")
            total_sent += sent

    def ping(self) -> bool:
        self._send_tlv(Commands.PING, [])
        resp = self._recv_tlv_response()
        if not resp:
            return False
        t, v = resp[0]
        return t == TlvTypes.NIL and v is None

    def set(self, key: str, value: str, ttl: int | None = None) -> bool:
        tlvs = [
            (TlvTypes.STR, key.encode()),
            (TlvTypes.STR, value.encode()),
        ]

        if ttl:
            tlvs.append(
                (TlvTypes.INT64, ttl.to_bytes(length=8, byteorder="big", signed=False))
            )

        self._send_tlv(Commands.SET, tlvs)
        resp = self._recv_tlv_response()
        return (
            len(resp) == 1
            and len(resp[0]) == 2
            and resp[0][0] == TlvTypes.STR
            and resp[0][1] == "Key set"
        )

    def get(self, key: str) -> str | int | None:
        self._send_tlv(
            Commands.GET,
            [
                (TlvTypes.STR, key.encode()),
            ],
        )
        resp = self._recv_tlv_response()
        if not resp or len(resp) != 1:
            return None
        tlv_type, tlv_value = resp[0]

        if (tlv_type == TlvTypes.STR or tlv_type == TlvTypes.INT64) and (
            isinstance(tlv_value, int) or isinstance(tlv_value, str)
        ):
            return tlv_value

        if tlv_value == TlvTypes.ERR:
            return None

        raise LightStashError("not implemented")

    def delete(self, key: str) -> bool:
        self._send_tlv(
            Commands.DELETE,
            [
                (TlvTypes.STR, key.encode()),
            ],
        )
        resp = self._recv_tlv_response()
        return (
            len(resp) == 1
            and len(resp[0]) == 2
            and resp[0][0] == TlvTypes.STR
            and resp[0][1] == "Entry deleted."
        )

    def expire(self, key: str, ttl_seconds: int) -> int:
        ttl_bytes = ttl_seconds.to_bytes(length=8, byteorder="big", signed=False)
        self._send_tlv(
            Commands.EXPIRE,
            [
                (TlvTypes.STR, key.encode()),
                (TlvTypes.INT64, ttl_bytes),
            ],
        )
        resp = self._recv_tlv_response()

        tlv_type, tlv_value = resp[0]
        if tlv_type == TlvTypes.INT64 and isinstance(tlv_value, int):
            return tlv_value

        raise LightStashError("TODO some error")

    def ttl(self, key: str) -> int | None:
        self._send_tlv(
            Commands.TTL,
            [
                (TlvTypes.STR, key.encode()),
            ],
        )
        resp = self._recv_tlv_response()
        if not resp or len(resp) != 1:
            raise LightStashError("something happend")

        tlv_type, tlv_value = resp[0]

        if (
            tlv_type == TlvTypes.INT64
            and isinstance(tlv_value, int)
            and tlv_value == -1
        ):
            return None

        if tlv_type == TlvTypes.INT64 and isinstance(tlv_value, int):
            return tlv_value

        raise LightStashError("TODO some error")

    def info(self) -> list[tuple[TlvTypes, Any]]:
        self._send_tlv(Commands.INFO, [])
        resp = self._recv_tlv_response()
        return resp

    # context management
    def __enter__(self) -> "LightStashClient":
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[object],
    ) -> None:
        self.disconnect()
