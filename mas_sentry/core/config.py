# SPDX-License-Identifier: AGPL-3.0-or-later
import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class MQTTConfig:
    host: str = "127.0.0.1"
    port: int = 1883
    username: str | None = None
    password: str | None = None
    tls: bool = False
    keepalive: int = 60
    client_id: str = "mas-sentry-001"


@dataclass
class AMQPConfig:
    host: str = "127.0.0.1"
    port: int = 5672
    username: str = "guest"
    password: str = "guest"
    vhost: str = "/"


@dataclass
class SentryConfig:
    mqtt: MQTTConfig = field(default_factory=MQTTConfig)
    amqp: AMQPConfig = field(default_factory=AMQPConfig)
    output_dir: Path = Path("reports/")
    verbose: bool = False
    timeout: int = 30

    @classmethod
    def from_file(cls, path: str) -> "SentryConfig":
        with open(path) as f:
            data = json.load(f)
        return cls(**data)

    def save(self, path: str):
        with open(path, "w") as f:
            json.dump(self.__dict__, f, indent=2, default=str)
