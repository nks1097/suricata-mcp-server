"""Cliente de comunicação com o Unix Domain Socket / Named Pipe de controle do Suricata."""

import json
import logging
import os
import socket
from pathlib import Path
from typing import Any

from .config import get_settings
from .exceptions import SuricataSocketError

logger = logging.getLogger("suricata_mcp.unix_socket")


class SuricataSocketClient:
    """Implementa o protocolo de comando e controle JSON-RPC do Suricata."""

    def __init__(self, socket_path: str | None = None, timeout: float = 5.0) -> None:
        settings = get_settings()
        self.socket_path = socket_path if socket_path is not None else settings.suricata_unix_socket_path
        self.timeout = timeout

    def is_available(self) -> bool:
        """Verifica se o soquete está configurado e acessível no sistema de arquivos."""
        if not self.socket_path:
            return False
        p = Path(self.socket_path)
        # No Unix, verifica se é socket. No Windows, verifica existência de arquivo/pipe.
        if os.name != "nt":
            return p.exists() and p.is_socket()
        return p.exists()

    def send_command(self, command: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        """Envia um comando JSON para o Suricata e aguarda a resposta."""
        if not self.socket_path:
            raise SuricataSocketError(
                "Unix socket não configurado. Defina 'SURICATA_UNIX_SOCKET_PATH' no .env para habilitar comandos via socket."
            )

        if not hasattr(socket, "AF_UNIX"):
            raise SuricataSocketError("Unix domain sockets não são suportados nesta plataforma.")

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            sock.connect(self.socket_path)

            # 1. Handshake inicial de versão do protocolo Suricata
            handshake = json.dumps({"version": "0.1"}) + "\n"
            sock.sendall(handshake.encode("utf-8"))

            raw_handshake_resp = self._read_json_response(sock)
            if raw_handshake_resp.get("return") != "OK":
                raise SuricataSocketError(f"Falha no handshake com o socket: {raw_handshake_resp}")

            # 2. Envio do comando solicitado
            payload: dict[str, Any] = {"command": command}
            if arguments:
                payload["arguments"] = arguments

            sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))
            response = self._read_json_response(sock)
            return response

        except TimeoutError as e:
            raise SuricataSocketError(f"Timeout de comunicação ({self.timeout}s) com o socket do Suricata.") from e
        except Exception as e:
            raise SuricataSocketError(f"Erro ao comunicar com o socket '{self.socket_path}': {e}") from e
        finally:
            sock.close()

    def _read_json_response(self, sock: socket.socket) -> dict[str, Any]:
        """Lê do stream até encontrar o fim da mensagem JSON."""
        buffer = ""
        while True:
            chunk = sock.recv(4096).decode("utf-8", errors="ignore")
            if not chunk:
                break
            buffer += chunk
            if "\n" in buffer:
                break
        try:
            parsed = json.loads(buffer.strip())
            return dict(parsed) if isinstance(parsed, dict) else {}
        except Exception as e:
            raise SuricataSocketError(f"Resposta JSON inválida do socket: {buffer}") from e

    def get_supported_commands(self) -> list[str]:
        """Obtém a lista de comandos suportados dinamicamente pela instância em execução."""
        try:
            resp = self.send_command("command-list")
            if resp.get("return") == "OK":
                cmds = resp.get("message", {}).get("commands", [])
                return list(cmds) if isinstance(cmds, list) else []
            return []
        except Exception:
            return []
