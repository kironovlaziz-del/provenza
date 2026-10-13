# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Network rules that leave an agent one way out: the Provenza egress proxy.

The proxy relays the agent's calls to Provenza (relay_provenza, /_provenza)
and checks every call to an external API, so the agent needs no other
destination - not Provenza, not DNS for the internet, nothing. Without such a
rule every control is cooperative: an agent that never asks is never refused.

  kubernetes  the proxy in its own namespace; a NetworkPolicy lets the agent
              pods reach only the proxy (and the cluster DNS that names it),
              another lets only those pods reach the proxy. Not a sidecar: a
              sidecar shares the pod's network, so the agent could use the
              proxy's way out too.
  docker      the agent on an internal network (no route out), the proxy on
              that network and on one with a way out.
  nftables    on a host or VM: the agent's Unix user may open connections to
              the proxy only; the proxy runs as another user.

Verify with an egress check (app/services/egress_check.py): the SDKs' egress
self-check, and require_confined_egress to make it a condition of acting.
"""

import ipaddress
import json
from typing import Any, Dict, List

from fastapi import status

from app.core.errors import api_error

# The listen address written into generated proxy configs (a container or host
# the operator deploys); Provenza itself binds nothing here.
ALL_INTERFACES = "0.0.0.0"  # nosec B104
PROXY_IMAGE = "provenza-proxy:0.1.0"   # built from proxy/: docker build -t provenza-proxy:0.1.0 proxy/


def _proxy_config(server_url: str, port: int, listen_host: str = ALL_INTERFACES) -> str:
    return json.dumps({"server_url": server_url, "proxy_key_file": "/etc/provenza/secret/proxy.key",
                       "listen": f"{listen_host}:{port}", "allow_non_loopback": listen_host != "127.0.0.1",
                       "relay_provenza": True}, indent=2)


def _indent(text: str, n: int) -> str:
    return "\n".join((" " * n + line) if line else line for line in text.splitlines())


def _kubernetes(server_url: str, proxy_port: int, namespace: str, proxy_namespace: str, agent_label: str,
                **_: Any) -> Dict[str, Any]:
    key, value = agent_label.split("=", 1)
    proxy = f"provenza-proxy.{proxy_namespace}.svc.cluster.local:{proxy_port}"
    manifest = f"""# The egress proxy in its own namespace: the only way out for agent pods.
apiVersion: v1
kind: Namespace
metadata:
  name: {proxy_namespace}
---
apiVersion: v1
kind: Secret
metadata:
  name: provenza-proxy
  namespace: {proxy_namespace}
type: Opaque
stringData:
  proxy.key: "pvz_proxy_..."   # Provenza: Gateways -> Egress -> Proxies -> New (shown once)
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: provenza-proxy
  namespace: {proxy_namespace}
data:
  proxy.json: |
{_indent(_proxy_config(server_url, proxy_port), 4)}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: provenza-proxy
  namespace: {proxy_namespace}
spec:
  replicas: 2
  selector:
    matchLabels: {{app: provenza-proxy}}
  template:
    metadata:
      labels: {{app: provenza-proxy}}
    spec:
      automountServiceAccountToken: false
      containers:
        - name: provenza-proxy
          image: {PROXY_IMAGE}
          args: ["-config", "/etc/provenza/proxy.json"]
          ports: [{{containerPort: {proxy_port}}}]
          securityContext:
            runAsNonRoot: true
            runAsUser: 65532
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities: {{drop: ["ALL"]}}
          volumeMounts:
            - {{name: config, mountPath: /etc/provenza/proxy.json, subPath: proxy.json, readOnly: true}}
            - {{name: secret, mountPath: /etc/provenza/secret, readOnly: true}}
      volumes:
        - name: config
          configMap: {{name: provenza-proxy}}
        - name: secret
          secret: {{secretName: provenza-proxy}}
---
apiVersion: v1
kind: Service
metadata:
  name: provenza-proxy
  namespace: {proxy_namespace}
spec:
  selector: {{app: provenza-proxy}}
  ports: [{{port: {proxy_port}, targetPort: {proxy_port}}}]
---
# Agent pods (label {agent_label}) reach the proxy and the cluster DNS - nothing else.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: provenza-agents-egress
  namespace: {namespace}
spec:
  podSelector:
    matchLabels: {{{json.dumps(key)}: {json.dumps(value)}}}
  policyTypes: [Egress]
  egress:
    - to:
        - namespaceSelector:
            matchLabels: {{kubernetes.io/metadata.name: {proxy_namespace}}}
          podSelector:
            matchLabels: {{app: provenza-proxy}}
      ports: [{{protocol: TCP, port: {proxy_port}}}]
    - to:
        - namespaceSelector:
            matchLabels: {{kubernetes.io/metadata.name: kube-system}}
          podSelector:
            matchLabels: {{k8s-app: kube-dns}}
      ports: [{{protocol: UDP, port: 53}}, {{protocol: TCP, port: 53}}]
---
# Only those agent pods may use the proxy (it holds the routes' credentials).
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: provenza-proxy-ingress
  namespace: {proxy_namespace}
spec:
  podSelector:
    matchLabels: {{app: provenza-proxy}}
  policyTypes: [Ingress]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels: {{kubernetes.io/metadata.name: {namespace}}}
          podSelector:
            matchLabels: {{{json.dumps(key)}: {json.dumps(value)}}}
      ports: [{{protocol: TCP, port: {proxy_port}}}]
"""
    return {
        "files": [{"name": "provenza-egress.yaml", "content": manifest}],
        "agent_env": {"PROVENZA_URL": f"http://{proxy}/_provenza",
                      "<ROUTE>_BASE_URL": f"http://{proxy}/<route>"},
        "notes": [
            f"Label the agent pods {agent_label}; the policy applies to them only.",
            "NetworkPolicy is enforced only by a CNI that implements it (Calico, Cilium, ...).",
            "The cluster DNS stays reachable so the proxy's name resolves; it answers cluster names. "
            "To also stop DNS lookups of outside names, point PROVENZA_URL at the proxy Service's IP and drop that rule.",
        ],
    }


def _docker(server_url: str, proxy_port: int, agent_service: str, **_: Any) -> Dict[str, Any]:
    compose = f"""# The agent has no route out: the "agents" network is internal. Only the
# proxy is also on a network with a way out.
services:
  provenza-proxy:
    image: {PROXY_IMAGE}
    command: ["-config", "/etc/provenza/proxy.json"]
    volumes:
      - ./proxy.json:/etc/provenza/proxy.json:ro
      - ./proxy.key:/etc/provenza/secret/proxy.key:ro
    networks: [agents, outside]
    restart: unless-stopped

  {agent_service}:
    # your agent's image and settings; only these lines matter here
    environment:
      PROVENZA_URL: http://provenza-proxy:{proxy_port}/_provenza
    networks: [agents]

networks:
  agents:
    internal: true
  outside: {{}}
"""
    return {
        "files": [{"name": "docker-compose.egress.yml", "content": compose},
                  {"name": "proxy.json", "content": _proxy_config(server_url, proxy_port) + "\n"}],
        "agent_env": {"PROVENZA_URL": f"http://provenza-proxy:{proxy_port}/_provenza",
                      "<ROUTE>_BASE_URL": f"http://provenza-proxy:{proxy_port}/<route>"},
        "notes": [
            "proxy.key: the proxy's key from Provenza (Gateways -> Egress -> Proxies -> New), mode 600.",
            f'Do not give the "{agent_service}" service any other network or "network_mode: host".',
        ],
    }


def _nftables(server_url: str, proxy_host: str, proxy_port: int, agent_user: str, **_: Any) -> Dict[str, Any]:
    if proxy_host in ("localhost", "127.0.0.1"):
        proxy_host = "127.0.0.1"
    try:
        ip = ipaddress.ip_address(proxy_host)
    except ValueError:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "egress_lockdown.ip_required")
    family = "ip" if ip.version == 4 else "ip6"
    loopback = ip.is_loopback
    rules = f"""#!/usr/sbin/nft -f
# Connections opened by the Unix user "{agent_user}" may go to the egress
# proxy only. Everything else it opens - other hosts, DNS, other local
# services - is dropped and logged. The proxy runs as another user.
table inet provenza_egress
delete table inet provenza_egress
table inet provenza_egress {{
  chain output {{
    type filter hook output priority filter; policy accept;
    meta skuid "{agent_user}" jump agent
  }}
  chain agent {{
    ct state established,related accept
    {family} daddr {ip} tcp dport {proxy_port} accept
    limit rate 10/minute log prefix "provenza-egress-drop " flags skuid
    drop
  }}
}}
"""
    unit = """# /etc/systemd/system/provenza-egress.service - load the rules at boot
[Unit]
Description=Provenza egress lockdown for the agent user
After=network-pre.target
Before=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f /etc/provenza/egress.nft
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""
    listen = "127.0.0.1" if loopback else ALL_INTERFACES
    base = f"http://{proxy_host if ip.version == 4 else '[' + proxy_host + ']'}:{proxy_port}"
    return {
        "files": [{"name": "egress.nft", "content": rules},
                  {"name": "provenza-egress.service", "content": unit},
                  {"name": "proxy.json", "content": _proxy_config(server_url, proxy_port, listen) + "\n"}],
        "agent_env": {"PROVENZA_URL": f"{base}/_provenza", "<ROUTE>_BASE_URL": f"{base}/<route>"},
        "notes": [
            f'Run the agent as the Unix user "{agent_user}" and the proxy as another one '
            "(proxy/deploy/provenza-proxy.service runs it as a dedicated user).",
            "Load: sudo install -m 600 egress.nft /etc/provenza/egress.nft && sudo nft -f /etc/provenza/egress.nft",
            "The proxy is addressed by IP: the agent needs no DNS, and none is allowed.",
        ],
    }


def render(kind: str, **params: Any) -> Dict[str, Any]:
    builder = {"kubernetes": _kubernetes, "docker": _docker, "nftables": _nftables}[kind]
    out = builder(**params)
    out["kind"] = kind
    out["verify"] = ("Then run the agent's egress self-check (agent.egress_selfcheck() in the SDKs): the agent "
                     "page shows the verdict, and Agent identity -> Require confined egress makes it a condition.")
    return out


def kinds() -> List[str]:
    return ["kubernetes", "docker", "nftables"]
