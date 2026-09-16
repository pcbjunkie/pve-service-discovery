#!/usr/bin/env python3
"""Discover web services in local Proxmox LXCs and publish them in Notes."""

from __future__ import annotations

import argparse
import configparser
import difflib
import fcntl
import html
import http.client
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Sequence


VERSION = "0.3.0"
DEFAULT_CONFIG = "/etc/pve-service-discovery.ini"
DEFAULT_LOCK = "/run/lock/pve-service-discovery.lock"
START_MARKER = "<!-- pve-service-discovery:start -->"
END_MARKER = "<!-- pve-service-discovery:end -->"
TITLE_RE = re.compile(r"<title\b[^>]*>(.*?)</title\s*>", re.IGNORECASE | re.DOTALL)
TAG_RE = re.compile(r"<[^>]+>")

DEFAULT_IGNORED_PORTS = {
    21, 22, 25, 53, 67, 68, 69, 110, 111, 123, 137, 138, 139, 143,
    389, 445, 465, 514, 587, 631, 636, 873, 989, 990, 993, 995,
    1080, 1194, 1812, 1813, 2049, 2375, 2376, 3306, 3389, 5432,
    5900, 5901, 5902, 6379, 6443, 8006, 9100, 27017,
}
DEFAULT_SECURE_PORTS = {443, 4443, 4430, 7443, 8443, 9443, 10443}

LOG = logging.getLogger("pve-service-discovery")


class DiscoveryError(RuntimeError):
    """A recoverable discovery or update failure."""


class MarkerError(DiscoveryError):
    """The managed Notes markers are malformed."""


@dataclass(frozen=True)
class Settings:
    timeout: float = 1.0
    workers: int = 16
    ignored_ports: frozenset[int] = frozenset(DEFAULT_IGNORED_PORTS)
    secure_ports: frozenset[int] = frozenset(DEFAULT_SECURE_PORTS)
    max_ips: int = 4
    max_ports: int = 64
    max_body_bytes: int = 65536
    max_description_bytes: int = 65536
    path_probe_limit: int = 6
    mark_stopped: bool = True
    include_templates: bool = False


@dataclass
class ContainerOverride:
    enabled: bool = True
    addresses: list[str] = field(default_factory=list)
    include_ports: set[int] = field(default_factory=set)
    ignore_ports: set[int] = field(default_factory=set)
    labels: dict[int, str] = field(default_factory=dict)
    paths: dict[int, str] = field(default_factory=dict)
    schemes: dict[int, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Container:
    vmid: int
    name: str
    status: str
    template: bool = False


@dataclass(frozen=True)
class Service:
    address: str
    port: int
    scheme: str
    url: str
    title: str
    status: int


@dataclass(frozen=True)
class HTTPResponse:
    status: int
    content_type: str
    body: bytes
    location: str = ""


def csv_ints(value: str, option: str) -> set[int]:
    result: set[int] = set()
    for raw in value.split(","):
        raw = raw.strip()
        if not raw:
            continue
        try:
            number = int(raw)
        except ValueError as exc:
            raise DiscoveryError(f"{option}: invalid port {raw!r}") from exc
        if not 1 <= number <= 65535:
            raise DiscoveryError(f"{option}: port out of range: {number}")
        result.add(number)
    return result


def load_config(path: str) -> tuple[Settings, configparser.ConfigParser]:
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str.lower
    if Path(path).exists():
        try:
            with open(path, "r", encoding="utf-8") as handle:
                parser.read_file(handle)
        except (OSError, configparser.Error) as exc:
            raise DiscoveryError(f"cannot read {path}: {exc}") from exc

    section = parser["discovery"] if parser.has_section("discovery") else {}

    def get_int(name: str, default: int, minimum: int, maximum: int) -> int:
        try:
            value = int(section.get(name, str(default)))
        except ValueError as exc:
            raise DiscoveryError(f"discovery.{name} must be an integer") from exc
        if not minimum <= value <= maximum:
            raise DiscoveryError(
                f"discovery.{name} must be between {minimum} and {maximum}"
            )
        return value

    def get_float(name: str, default: float, minimum: float, maximum: float) -> float:
        try:
            value = float(section.get(name, str(default)))
        except ValueError as exc:
            raise DiscoveryError(f"discovery.{name} must be a number") from exc
        if not minimum <= value <= maximum:
            raise DiscoveryError(
                f"discovery.{name} must be between {minimum} and {maximum}"
            )
        return value

    def get_bool(name: str, default: bool) -> bool:
        if not parser.has_section("discovery") or name not in section:
            return default
        try:
            return parser.getboolean("discovery", name)
        except ValueError as exc:
            raise DiscoveryError(f"discovery.{name} must be true or false") from exc

    ignored = csv_ints(
        section.get("ignored_ports", ",".join(map(str, sorted(DEFAULT_IGNORED_PORTS)))),
        "discovery.ignored_ports",
    )
    secure = csv_ints(
        section.get("secure_ports", ",".join(map(str, sorted(DEFAULT_SECURE_PORTS)))),
        "discovery.secure_ports",
    )
    settings = Settings(
        timeout=get_float("timeout", 1.0, 0.1, 30.0),
        workers=get_int("workers", 16, 1, 128),
        ignored_ports=frozenset(ignored),
        secure_ports=frozenset(secure),
        max_ips=get_int("max_ips", 4, 1, 32),
        max_ports=get_int("max_ports", 64, 1, 1024),
        max_body_bytes=get_int("max_body_bytes", 65536, 1024, 1048576),
        max_description_bytes=get_int(
            "max_description_bytes", 65536, 1024, 1048576
        ),
        path_probe_limit=get_int("path_probe_limit", 6, 0, 20),
        mark_stopped=get_bool("mark_stopped", True),
        include_templates=get_bool("include_templates", False),
    )
    return settings, parser


def container_override(parser: configparser.ConfigParser, vmid: int) -> ContainerOverride:
    name = f"container:{vmid}"
    if not parser.has_section(name):
        return ContainerOverride()
    section = parser[name]
    override = ContainerOverride()
    try:
        override.enabled = section.getboolean("enabled", fallback=True)
    except ValueError as exc:
        raise DiscoveryError(f"{name}.enabled must be true or false") from exc

    addresses = section.get("addresses", "")
    if addresses.strip():
        for raw in addresses.split(","):
            raw = raw.strip()
            try:
                parsed = ipaddress.ip_address(raw)
            except ValueError as exc:
                raise DiscoveryError(f"{name}.addresses: invalid address {raw!r}") from exc
            if parsed.version != 4:
                raise DiscoveryError(f"{name}.addresses: only IPv4 is supported")
            override.addresses.append(str(parsed))

    override.include_ports = csv_ints(section.get("include_ports", ""), f"{name}.include_ports")
    override.ignore_ports = csv_ints(section.get("ignore_ports", ""), f"{name}.ignore_ports")

    for key, value in section.items():
        match = re.fullmatch(r"(label|path|scheme)\.(\d+)", key)
        if not match:
            continue
        kind, port_text = match.groups()
        port = int(port_text)
        if not 1 <= port <= 65535:
            raise DiscoveryError(f"{name}.{key}: port out of range")
        value = value.strip()
        if kind == "label":
            override.labels[port] = value
        elif kind == "path":
            if not value.startswith("/"):
                raise DiscoveryError(f"{name}.{key} must start with /")
            override.paths[port] = value
        else:
            if value not in {"http", "https"}:
                raise DiscoveryError(f"{name}.{key} must be http or https")
            override.schemes[port] = value
    return override


def run_command(args: Sequence[str], timeout: float = 30.0) -> str:
    try:
        result = subprocess.run(
            list(args),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DiscoveryError(f"command failed: {args[0]}: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise DiscoveryError(f"{args[0]} failed: {detail}")
    return result.stdout


def run_json(args: Sequence[str]) -> object:
    output = run_command(args)
    try:
        return json.loads(output)
    except json.JSONDecodeError as exc:
        raise DiscoveryError(f"{args[0]} returned invalid JSON") from exc


def local_node() -> str:
    return socket.gethostname().split(".", 1)[0]


def list_containers(node: str) -> list[Container]:
    raw = run_json(["pvesh", "get", f"/nodes/{node}/lxc", "--output-format", "json"])
    if isinstance(raw, dict) and isinstance(raw.get("data"), list):
        raw = raw["data"]
    if not isinstance(raw, list):
        raise DiscoveryError("unexpected LXC list returned by pvesh")
    containers: list[Container] = []
    for item in raw:
        if not isinstance(item, dict) or "vmid" not in item:
            continue
        containers.append(
            Container(
                vmid=int(item["vmid"]),
                name=str(item.get("name") or item.get("hostname") or f"CT {item['vmid']}"),
                status=str(item.get("status") or "unknown"),
                template=bool(int(item.get("template") or 0)),
            )
        )
    return sorted(containers, key=lambda item: item.vmid)


def get_container_config(node: str, vmid: int) -> dict[str, object]:
    raw = run_json(
        ["pvesh", "get", f"/nodes/{node}/lxc/{vmid}/config", "--output-format", "json"]
    )
    if isinstance(raw, dict) and isinstance(raw.get("data"), dict):
        raw = raw["data"]
    if not isinstance(raw, dict):
        raise DiscoveryError(f"CT {vmid}: unexpected config returned by pvesh")
    return raw


def set_description(node: str, vmid: int, description: str, digest: str = "") -> None:
    args = [
        "pvesh", "set", f"/nodes/{node}/lxc/{vmid}/config",
        "--description", description,
    ]
    if digest:
        args.extend(["--digest", digest])
    run_command(args)


def pct_exec(vmid: int, command: Sequence[str], timeout: float = 20.0) -> str:
    return run_command(["pct", "exec", str(vmid), "--", *command], timeout=timeout)


def usable_ipv4(value: str) -> Optional[str]:
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return None
    if address.version != 4 or address.is_loopback or address.is_link_local or address.is_multicast:
        return None
    return str(address)


def discover_addresses(vmid: int, maximum: int) -> list[str]:
    addresses: list[str] = []
    try:
        raw = pct_exec(vmid, ["ip", "-j", "-4", "addr", "show", "scope", "global"])
        data = json.loads(raw)
        for interface in data:
            for info in interface.get("addr_info", []):
                if info.get("family") != "inet":
                    continue
                address = usable_ipv4(str(info.get("local", "")))
                if address and address not in addresses:
                    addresses.append(address)
    except (DiscoveryError, json.JSONDecodeError, TypeError):
        LOG.debug("CT %s: ip JSON lookup failed; trying hostname -I", vmid)

    if not addresses:
        try:
            raw = pct_exec(vmid, ["hostname", "-I"])
            for candidate in raw.split():
                address = usable_ipv4(candidate)
                if address and address not in addresses:
                    addresses.append(address)
        except DiscoveryError:
            pass
    return addresses[:maximum]


def parse_ss_ports(output: str) -> set[int]:
    ports: set[int] = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        local = fields[3]
        if ":" not in local:
            continue
        raw_port = local.rsplit(":", 1)[1]
        if raw_port.isdigit():
            port = int(raw_port)
            if 1 <= port <= 65535:
                ports.add(port)
    return ports


def parse_proc_net_tcp(output: str) -> set[int]:
    ports: set[int] = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 4 or fields[0].lower().startswith("sl"):
            continue
        if fields[3].upper() != "0A" or ":" not in fields[1]:
            continue
        try:
            port = int(fields[1].rsplit(":", 1)[1], 16)
        except ValueError:
            continue
        if 1 <= port <= 65535:
            ports.add(port)
    return ports


def discover_ports(vmid: int) -> set[int]:
    try:
        return parse_ss_ports(pct_exec(vmid, ["ss", "-H", "-lnt"]))
    except DiscoveryError:
        LOG.debug("CT %s: ss failed; trying /proc/net/tcp", vmid)
    ports: set[int] = set()
    for proc_file in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            ports.update(parse_proc_net_tcp(pct_exec(vmid, ["cat", proc_file])))
        except DiscoveryError:
            continue
    return ports


def extract_title(body: bytes, content_type: str) -> str:
    charset = "utf-8"
    match = re.search(r"charset\s*=\s*[\"']?([^\s;\"']+)", content_type, re.I)
    if match:
        charset = match.group(1)
    try:
        text = body.decode(charset, errors="replace")
    except LookupError:
        text = body.decode("utf-8", errors="replace")
    match = TITLE_RE.search(text)
    if not match:
        return ""
    title = html.unescape(TAG_RE.sub("", match.group(1)))
    title = " ".join(title.split())
    return title[:120]


def fetch_http(
    address: str,
    port: int,
    scheme: str,
    path: str,
    timeout: float,
    max_body_bytes: int,
) -> Optional[HTTPResponse]:
    connection: http.client.HTTPConnection
    try:
        if scheme == "https":
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            connection = http.client.HTTPSConnection(
                address, port, timeout=timeout, context=context
            )
        else:
            connection = http.client.HTTPConnection(address, port, timeout=timeout)
        connection.request(
            "GET",
            path,
            headers={
                "User-Agent": f"pve-service-discovery/{VERSION}",
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.1",
                "Connection": "close",
                "Range": f"bytes=0-{max_body_bytes - 1}",
            },
        )
        response = connection.getresponse()
        body = response.read(max_body_bytes)
        return HTTPResponse(
            response.status,
            response.getheader("Content-Type", ""),
            body,
            response.getheader("Location", ""),
        )
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError):
        return None
    finally:
        try:
            connection.close()
        except (UnboundLocalError, OSError):
            pass


def markdown_label(value: str) -> str:
    value = value.replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]")
    return value.replace("\n", " ").replace("\r", " ").strip()


def derived_paths(container_name: str, limit: int) -> list[str]:
    """Create plausible application paths without maintaining an app database."""
    if limit <= 0:
        return []
    normalized = re.sub(r"[^a-z0-9._-]+", "-", container_name.lower()).strip("-._")
    tokens = [item for item in re.split(r"[._-]+", normalized) if len(item) >= 3]
    generic = {"apache", "server", "service", "container", "linux", "debian", "ubuntu"}
    candidates: list[str] = []

    # The most specific product word is commonly last: apache-guacamole -> guacamole.
    for token in reversed(tokens):
        if token not in generic:
            candidates.append(f"/{token}/")
    if normalized and len(tokens) > 1:
        candidates.append(f"/{normalized}/")

    result: list[str] = []
    for path in candidates:
        if path != "/" and path not in result:
            result.append(path)
    return result[:limit]


def redirect_path(location: str, address: str, port: int, scheme: str) -> str:
    """Return a same-origin redirect path, or an empty string."""
    if not location:
        return ""
    base = f"{scheme}://{address}:{port}/"
    try:
        target = urllib.parse.urlsplit(urllib.parse.urljoin(base, location))
    except ValueError:
        return ""
    if target.scheme != scheme or target.hostname != address:
        return ""
    target_port = target.port or (443 if target.scheme == "https" else 80)
    if target_port != port:
        return ""
    path = target.path or "/"
    if target.query:
        path += "?" + target.query
    return path


def generic_or_error_page(response: HTTPResponse, title: str) -> bool:
    if response.status >= 400:
        return True
    lowered = title.lower()
    generic_phrases = (
        "not found",
        "http status 404",
        "apache tomcat",
        "welcome to nginx",
        "index of /",
        "iis windows server",
    )
    return not title or any(phrase in lowered for phrase in generic_phrases)


def useful_response(response: HTTPResponse) -> bool:
    return 200 <= response.status < 400 or response.status in {401, 403}


def distinct_response(candidate: HTTPResponse, root: HTTPResponse) -> bool:
    return (
        candidate.status,
        candidate.content_type,
        candidate.body,
        candidate.location,
    ) != (root.status, root.content_type, root.body, root.location)


def probe_endpoint(
    address: str,
    port: int,
    container_name: str,
    settings: Settings,
    override: ContainerOverride,
) -> list[Service]:
    configured_path = override.paths.get(port)
    forced_scheme = override.schemes.get(port)
    if forced_scheme:
        schemes = [forced_scheme]
    elif port in settings.secure_ports or str(port).endswith("443"):
        schemes = ["https", "http"]
    else:
        schemes = ["http", "https"]

    for scheme in schemes:
        root_path = configured_path or "/"
        root_response = fetch_http(
            address, port, scheme, root_path, settings.timeout, settings.max_body_bytes
        )
        if root_response is None:
            continue
        lower_body = root_response.body[:4096].lower()
        if (
            scheme == "http"
            and root_response.status == 400
            and b"https" in lower_body
            and (b"plain http" in lower_body or b"http request" in lower_body)
        ):
            continue

        root_title = extract_title(root_response.body, root_response.content_type)
        LOG.debug(
            "probe %s://%s:%s%s -> status=%s bytes=%s title=%r",
            scheme,
            address,
            port,
            root_path,
            root_response.status,
            len(root_response.body),
            root_title,
        )

        responses: list[tuple[str, HTTPResponse, str]] = []

        if configured_path is None:
            candidates: list[str] = []
            redirected = redirect_path(root_response.location, address, port, scheme)
            if redirected and redirected != "/":
                candidates.append(redirected)
            if generic_or_error_page(root_response, root_title):
                candidates.extend(derived_paths(container_name, settings.path_probe_limit))

            seen = {"/"}
            for candidate in candidates:
                if candidate in seen:
                    continue
                seen.add(candidate)
                candidate_response = fetch_http(
                    address,
                    port,
                    scheme,
                    candidate,
                    settings.timeout,
                    settings.max_body_bytes,
                )
                if candidate_response is None:
                    continue
                candidate_title = extract_title(
                    candidate_response.body, candidate_response.content_type
                )
                LOG.debug(
                    "probe %s://%s:%s%s -> status=%s bytes=%s title=%r "
                    "useful=%s same_as_root=%s",
                    scheme,
                    address,
                    port,
                    candidate,
                    candidate_response.status,
                    len(candidate_response.body),
                    candidate_title,
                    useful_response(candidate_response),
                    not distinct_response(candidate_response, root_response),
                )
                if useful_response(candidate_response) and distinct_response(
                    candidate_response, root_response
                ):
                    responses.append((candidate, candidate_response, candidate_title))

        # Keep a useful root endpoint. If the root is dead, retain it only when
        # no working nested application was found, preserving prior behavior.
        if useful_response(root_response) or not responses:
            responses.insert(0, (root_path, root_response, root_title))

        services: list[Service] = []
        for path, response, discovered_title in responses:
            title = override.labels.get(port) or discovered_title
            if not title:
                suffix = f" ({path})" if path != "/" else ""
                title = f"Open {container_name}{suffix}"
            title = markdown_label(title)
            url = f"{scheme}://{address}:{port}{path}"
            services.append(
                Service(address, port, scheme, url, title, response.status)
            )
            LOG.debug("accepted %s for CT %s", url, container_name)
        return services
    return []


def discover_services(
    addresses: Sequence[str],
    ports: Sequence[int],
    container_name: str,
    settings: Settings,
    override: ContainerOverride,
) -> list[Service]:
    jobs = [(address, port) for address in addresses for port in ports]
    services: list[Service] = []
    if not jobs:
        return services
    with ThreadPoolExecutor(max_workers=settings.workers) as executor:
        future_map = {
            executor.submit(
                probe_endpoint, address, port, container_name, settings, override
            ): (address, port)
            for address, port in jobs
        }
        for future in as_completed(future_map):
            try:
                endpoint_services = future.result()
            except Exception as exc:  # one odd endpoint must not abort a CT scan
                address, port = future_map[future]
                LOG.debug("probe %s:%s failed: %s", address, port, exc)
                continue
            services.extend(endpoint_services)
    address_order = {address: index for index, address in enumerate(addresses)}
    return sorted(
        services, key=lambda item: (address_order[item.address], item.port, item.url)
    )


def build_managed_block(
    container: Container,
    addresses: Sequence[str],
    services: Sequence[Service],
) -> str:
    lines = [START_MARKER, "### Discovered services", ""]
    if container.status != "running":
        lines.append(f"_CT {container.vmid} is {container.status}; discovery will resume when it runs._")
    else:
        if addresses:
            address_text = ", ".join(f"`{address}`" for address in addresses)
            lines.append(f"**IPv4:** {address_text}")
            lines.append("")
        else:
            lines.append("_No usable IPv4 address was detected._")

        if services:
            duplicate_titles: dict[str, int] = {}
            for service in services:
                duplicate_titles[service.title] = duplicate_titles.get(service.title, 0) + 1
            for service in services:
                label = service.title
                if duplicate_titles[label] > 1:
                    path = urllib.parse.urlsplit(service.url).path or "/"
                    label = f"{label} — {service.scheme} {path}"
                lines.append(
                    f"- [{label}]({service.url}) — `{service.address}:{service.port}`"
                )
        elif addresses:
            lines.append("_No HTTP or HTTPS services responded._")
    lines.extend(["", "_Automatically managed; notes outside this block are preserved._", END_MARKER])
    return "\n".join(lines)


def merge_managed_block(description: str, block: str) -> str:
    start_count = description.count(START_MARKER)
    end_count = description.count(END_MARKER)
    if start_count != end_count or start_count > 1:
        raise MarkerError("managed Notes markers are missing, duplicated, or unbalanced")
    if start_count == 1:
        start = description.index(START_MARKER)
        end = description.index(END_MARKER, start) + len(END_MARKER)
        return description[:start] + block + description[end:]
    if not description:
        return block
    separator = "\n" if description.endswith("\n") else "\n\n"
    return description + separator + block


def remove_managed_block(description: str) -> str:
    start_count = description.count(START_MARKER)
    end_count = description.count(END_MARKER)
    if start_count != end_count or start_count > 1:
        raise MarkerError("managed Notes markers are missing, duplicated, or unbalanced")
    if not start_count:
        return description
    start = description.index(START_MARKER)
    end = description.index(END_MARKER, start) + len(END_MARKER)
    before = description[:start].rstrip("\n")
    after = description[end:].lstrip("\n")
    if before and after:
        return before + "\n\n" + after
    return before or after


def show_diff(vmid: int, old: str, new: str) -> None:
    diff = difflib.unified_diff(
        old.splitlines(),
        new.splitlines(),
        fromfile=f"CT-{vmid}-notes.before",
        tofile=f"CT-{vmid}-notes.after",
        lineterm="",
    )
    for line in diff:
        print(line)


def acquire_lock(path: str):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    handle = open(path, "w", encoding="utf-8")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        handle.close()
        raise DiscoveryError("another discovery scan is already running") from exc
    return handle


def process_container(
    node: str,
    container: Container,
    settings: Settings,
    parser: configparser.ConfigParser,
    dry_run: bool,
    remove: bool,
) -> bool:
    override = container_override(parser, container.vmid)
    if not override.enabled:
        LOG.info("CT %s (%s): disabled by configuration", container.vmid, container.name)
        return False
    config = get_container_config(node, container.vmid)
    old_description = str(config.get("description") or "")
    digest = str(config.get("digest") or "")

    if remove:
        new_description = remove_managed_block(old_description)
    elif container.status != "running":
        if not settings.mark_stopped:
            LOG.info("CT %s (%s): stopped; skipped", container.vmid, container.name)
            return False
        new_description = merge_managed_block(
            old_description, build_managed_block(container, [], [])
        )
    else:
        addresses = override.addresses or discover_addresses(container.vmid, settings.max_ips)
        ports = discover_ports(container.vmid) | override.include_ports
        ports -= settings.ignored_ports | override.ignore_ports
        sorted_ports = sorted(ports)[: settings.max_ports]
        if len(ports) > settings.max_ports:
            LOG.warning(
                "CT %s (%s): limiting %s candidate ports to %s",
                container.vmid, container.name, len(ports), settings.max_ports,
            )
        services = discover_services(
            addresses, sorted_ports, container.name, settings, override
        )
        LOG.info(
            "CT %s (%s): %s address(es), %s candidate port(s), %s web service(s)",
            container.vmid, container.name, len(addresses), len(sorted_ports), len(services),
        )
        new_description = merge_managed_block(
            old_description, build_managed_block(container, addresses, services)
        )

    if new_description == old_description:
        LOG.debug("CT %s (%s): Notes unchanged", container.vmid, container.name)
        return False
    if len(new_description.encode("utf-8")) > settings.max_description_bytes:
        raise DiscoveryError(
            f"CT {container.vmid}: updated Notes exceed max_description_bytes; skipped"
        )
    if dry_run:
        show_diff(container.vmid, old_description, new_description)
    else:
        set_description(node, container.vmid, new_description, digest)
        LOG.info("CT %s (%s): Notes updated", container.vmid, container.name)
    return True


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=DEFAULT_CONFIG, help="INI configuration path")
    parser.add_argument("--dry-run", action="store_true", help="show Notes diffs without writing")
    parser.add_argument(
        "--vmid", action="append", type=int, help="only scan this CT ID (repeatable)"
    )
    parser.add_argument(
        "--remove-managed-notes",
        action="store_true",
        help="remove this tool's marked Notes section instead of discovering",
    )
    parser.add_argument("--verbose", action="store_true", help="enable debug logging")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )
    if os.geteuid() != 0:
        LOG.error("run this command as root on a Proxmox VE node")
        return 2
    for command in ("pvesh", "pct"):
        if shutil.which(command) is None:
            LOG.error("%s was not found; run this on a Proxmox VE node", command)
            return 2

    try:
        settings, parser = load_config(args.config)
        with acquire_lock(DEFAULT_LOCK):
            node = local_node()
            containers = list_containers(node)
            if args.vmid:
                selected = set(args.vmid)
                containers = [item for item in containers if item.vmid in selected]
                missing = selected - {item.vmid for item in containers}
                if missing:
                    raise DiscoveryError(
                        "CT ID(s) not found on this node: " + ", ".join(map(str, sorted(missing)))
                    )
            if not settings.include_templates:
                containers = [item for item in containers if not item.template]

            changed = 0
            errors = 0
            for container in containers:
                try:
                    changed += int(
                        process_container(
                            node,
                            container,
                            settings,
                            parser,
                            args.dry_run,
                            args.remove_managed_notes,
                        )
                    )
                except DiscoveryError as exc:
                    errors += 1
                    LOG.error("CT %s (%s): %s", container.vmid, container.name, exc)
            LOG.info(
                "scan complete: %s container(s), %s change(s), %s error(s)",
                len(containers), changed, errors,
            )
            return 1 if errors else 0
    except DiscoveryError as exc:
        LOG.error("%s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
