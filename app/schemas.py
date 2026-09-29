"""Request schemas and validation for the audit API."""

from __future__ import annotations

import ipaddress
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

AUDIT_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
RULE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
MAX_RULES = 18
PORT_MIN = 0
PORT_MAX = 65535


def parse_cidr(value: str) -> tuple[int, int]:
    """Validate an IPv4 CIDR and return its inclusive uint32 interval.

    Strict parsing: host bits must be zero (``10.0.0.1/24`` is rejected;
    write ``10.0.0.0/24``).  A bare address is accepted as a /32.
    """
    try:
        net = ipaddress.IPv4Network(value, strict=True)
    except ValueError as exc:
        raise ValueError(
            f"非法 IPv4 CIDR: {value!r}（需为合法网络地址，主机位须为 0，例如 10.0.0.0/8）"
        ) from exc
    return int(net.network_address), int(net.broadcast_address)


class PortRange(BaseModel):
    """Closed port interval [start, end] within 0..65535."""

    start: int = Field(ge=PORT_MIN, le=PORT_MAX)
    end: int = Field(ge=PORT_MIN, le=PORT_MAX)

    @model_validator(mode="after")
    def _ordered(self) -> "PortRange":
        if self.end < self.start:
            raise ValueError(
                f"端口区间下界 {self.start} 不得大于上界 {self.end}"
            )
        return self


class Rule(BaseModel):
    id: str = Field(pattern=RULE_ID_PATTERN)
    protocol: Literal["tcp", "udp", "both"]
    src_cidr: str
    dst_cidr: str
    src_port: PortRange
    dst_port: PortRange

    @field_validator("src_cidr", "dst_cidr")
    @classmethod
    def _cidr_ok(cls, value: str) -> str:
        parse_cidr(value)
        return value


class AuditRequest(BaseModel):
    audit_id: str = Field(pattern=AUDIT_ID_PATTERN)
    rules: list[Rule] = Field(min_length=1, max_length=MAX_RULES)

    @model_validator(mode="after")
    def _unique_rule_ids(self) -> "AuditRequest":
        ids = [rule.id for rule in self.rules]
        duplicates = sorted({rid for rid in ids if ids.count(rid) > 1})
        if duplicates:
            raise ValueError(f"规则标识重复: {', '.join(duplicates)}")
        return self
