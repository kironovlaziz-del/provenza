# Provenza egress sensor

The sensor is the kernel-side half of Provenza: it enforces the egress
policy on every governed cgroup of a host, resolves DNS for the workloads
it contains, and reports what it blocked back to Provenza.

The sensor is a single static binary plus one embedded eBPF object. There
is nothing to install from a package manager and no runtime dependency
beyond the kernel.

## What it does

- **Egress containment.** cgroup v2 BPF programs (`connect`, `sendmsg`,
  `recvmsg`, `getpeername`, `sock_create`, `egress`, `ingress`) decide, for
  every socket operation, whether the workload is allowed to reach the
  destination. Optional: a BPF LSM program for non-IP socket families and
  cgroup tracepoints for cgroups created after the sensor started.
- **DNS mediation.** For workloads with `dns: listed`, the sensor runs a
  per-workload DNS listener on `127.0.0.1:<port>`, filters queries against
  the workload's allow list, forwards the rest to the host's resolvers,
  and feeds the resolved addresses back into the kernel allow map.
- **Generation swap.** A new policy is written as generation N+1 and
  switched with a single map write. Programs that read the old generation
  finish before its entries are deleted, so there is no window with an
  inconsistent policy.
- **Restart safety.** Pinned links in bpffs keep containment in force
  while the daemon restarts. The last policy is cached on disk and
  re-applied at startup even if Provenza is unreachable.
- **`run` subcommand.** `provenza-sensor run --agent N -- cmd` asks the
  running daemon for a dedicated cgroup, moves the child into it, and
  execs the command. The cgroup is named `provenza-agent-N-<random>` and
  is removed when the last process exits.
- **Signed commands.** The control plane can queue one of three
  operations for a sensor — detach, restart, dump-state — each signed
  with the organization's Ed25519 key and delivered on the next
  heartbeat. See `docs/sensor-commands.md`.

## Requirements

- Linux 5.15+ with cgroup v2, BPF, and BTF enabled.
- Root (or `CAP_BPF`, `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`).
- `clang >= 14` for rebuilding the BPF object (not needed to run).
- Go 1.26+ for rebuilding the sensor (not needed to run).

## Build

    make bpf    # rebuild the kernel program (clang >= 14)
    make build  # the provenza-sensor binary (BPF object is embedded)
    make test   # unit tests and go vet

The BPF object at `internal/bpfobj/sensor.bpf.o` is embedded into the
binary with `//go:embed`, so the deployed binary is self-contained.

## Install

The usual way needs neither this repository nor Go: in Provenza, Gateways
→ **Runtime** → **Register sensor** gives a key and the command to run on
the host. The control plane serves the install script, the binary and the
systemd unit, and the script checks them against its `SHA256SUMS`:

    f=$(mktemp) && curl -fsSL https://provenza.example.com/api/v1/egress-sensor/download/install.sh -o "$f" \
      && sudo bash "$f" --url https://provenza.example.com

The script asks for the key with the input hidden, so it stays out of the
shell history and the process list (`--key-file PATH` or
`PROVENZA_SENSOR_KEY` for unattended installs). It checks the host (kernel,
cgroup v2, BTF), installs the binary and the unit, enrolls the sensor - which writes `sensor.json`, the key, the
sensor id and the organization's command-signing key under
`/etc/provenza-sensor/` - and starts it. From a checkout, `sudo ./sensor/install.sh --url ...`
does the same with a binary built here; `--help` lists the flags.

By hand, with a binary you built:

    sudo install -m 0755 provenza-sensor /usr/local/bin/
    sudo cp packaging/provenzasensor.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable provenzasensor
    # writes sensor.json, the key, the sensor id and the signing key, then (re)starts the service
    sudo provenza-sensor enroll --url https://provenza.example.com   # asks for the key

To remove the sensor's kernel state and cache:

    sudo provenza-sensor --uninstall

This detaches every pinned link and removes the cached policy. It does
not remove the binary or the systemd unit — that is the package
manager's job.

## Configuration

`/etc/provenza-sensor/sensor.json`:

    {
      "provenza_url": "https://provenza.example.com",
      "key_file": "/etc/provenza-sensor/key",
      "ca_file": "/etc/provenza-sensor/ca.pem",
      "cgroup_root": "/sys/fs/cgroup",
      "attach_cgroup": "/sys/fs/cgroup",
      "pin_dir": "/sys/fs/bpf/provenza",
      "state_dir": "/var/lib/provenza-sensor",
      "run_socket": "/run/provenza-sensor/run.sock",
      "run_group": "provenza",
      "ring_bytes": 262144,
      "signing_key_file": "/etc/provenza-sensor/signing-key.pub",
      "sensor_id_file": "/etc/provenza-sensor/sensor-id"
    }

All fields have sensible defaults. `PROVENZA_URL` and
`PROVENZA_SENSOR_KEY` override the file. The key must start with
`pvz_sensor_`; its file is read with mode 0600.

| Field | Meaning |
|---|---|
| `provenza_url` | Control plane URL. `https` unless it is on this host. |
| `key_file` | File containing the sensor key. |
| `ca_file` | Extra CA for Provenza's TLS. Empty = system roots. |
| `cgroup_root` | cgroup v2 mount. Usually `/sys/fs/cgroup`. |
| `attach_cgroup` | Where the programs attach. Empty = `cgroup_root`. |
| `pin_dir` | bpffs directory for pinned links. |
| `state_dir` | Where the last policy is cached. |
| `run_socket` | Unix socket for the `run` subcommand. |
| `run_group` | Group allowed to use the run socket. Empty = root only. |
| `ring_bytes` | Ring buffer size (power of two). 0 = object's default. |
| `signing_key_file` | The organization's public key that signs commands (written by `enroll`). |
| `sensor_id_file` | This sensor's id, which signed commands must name (written by `enroll`). |

## How it talks to Provenza

- `GET /api/v1/egress-sensor/config` with `If-None-Match: "<version>"`.
  `304 Not Modified` means the current policy is still in force. The
  sensor polls at `refresh_seconds` from the policy it is enforcing.
- `POST /api/v1/egress-sensor/heartbeat` with `Heartbeat`, every
  `heartbeat_seconds` (10-120 s). Includes the hooks that are actually
  attached, warnings (e.g. missing LSM), and the count of dropped events;
  the answer carries the pending signed commands. Provenza counts a
  sensor as offline after three missed heartbeats, and not before 5
  minutes.
- `POST /api/v1/egress-sensor/violations` and `.../activity` (the sample
  of allowed connections) with batches of up to 500 events. The client
  splits larger batches; events the server refuses as a whole are kept and
  retried, a bad event is isolated and dropped.

Authentication is `X-Sensor-Key: pvz_sensor_...`. A revoked key yields
`401` or `403`, which the client reports as `ErrUnauthorized`; the sensor
keeps the current policy and keeps retrying.

## Commands

An admin can queue one of three operations for a sensor from the
Runtime page (expand the sensor's row):

- **Dump state** — the sensor sends back its own snapshot, the same JSON
  `provenza-sensor status --json` prints locally.
- **Restart** — systemd restarts the daemon; pinned BPF links keep
  enforcement across the restart.
- **Detach** — full uninstall on the host. Irreversible from the sensor
  side; re-enroll to bring the sensor back.

Every command is signed with the organization's Ed25519 key and verified
by the sensor before anything happens. The key and the sensor's own id
are written by `enroll` and live in
`/etc/provenza-sensor/signing-key.pub` and
`/etc/provenza-sensor/sensor-id`. A missing key (an older install that
was never re-enrolled) is a warning, not an error: the sensor still
enforces policy, it just refuses every command.

The full model, including what a stolen signing key can and cannot do,
is in `docs/sensor-commands.md`.

## Troubleshooting

**The sensor does not attach.** Check `journalctl -u provenzasensor`.
Common causes: cgroup v2 is not mounted at `cgroup_root`; the kernel is
older than 5.15; BPF LSM is disabled (`lsm=...` in the kernel command
line). LSM is optional — the sensor reports it as a warning, not an
error.

**Nothing is blocked.** Check `d.kernel.Hooks` in the heartbeat: it lists
the hooks that actually attached. If `connect4` is missing, the core
programs were not loaded; the log at startup shows why.

**DNS does not resolve for a workload.** The workload must have
`dns: listed` or `dns: any` in the policy. The per-workload listener is
bound to `127.0.0.1:<port>`; the kernel redirects queries to it. Check
`ss -lunp | grep 153` to see the listeners.

**Containment survives a crash.** That is by design: pinned links stay
attached until `--uninstall` or `kern.Detach` is called. To recover, run
`sudo provenza-sensor --uninstall` and restart the service.

## Development

    go vet ./...
    go test ./...

Kernel tests need root and a machine with BPF:

    sudo make test-kernel

They exercise the actual programs against the running kernel: allowed
and denied TCP and UDP, DNS redirection, raw sockets, ingress, isolation,
and generation swap.

## License

Apache License, Version 2.0.
