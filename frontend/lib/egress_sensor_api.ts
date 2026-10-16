// Egress sensor: hosts running the provenza-sensor daemon, the workloads it
// governs, and the violations it reported.
// Backend: app/api/egress_sensor.py, /api/v1/egress-sensor.
//
// The admin side uses the same JWT as the rest of the product; the sensor
// side (GET /config, POST /heartbeat, POST /violations) is not reached from
// the browser and lives in the daemon under sensor/.
import { api } from "./api";

// ---------------------------------------------------------------- sensors

export interface SensorT {
  id: number;
  org_id: number;
  name: string;
  hostname: string | null;
  key_prefix: string;
  enabled: boolean;
  revoked_at: string | null;

  version: string | null;
  kernel: string | null;
  enforcing: boolean | null;
  hooks: string[] | null;
  warnings: string[] | null;
  errors: string[] | null;
  dropped_events: number;
  config_version: string | null;
  last_seen_at: string | null;

  created_at: string;
  updated_at: string | null;
}

export interface SensorCreatedT extends SensorT {
  /** Returned exactly once at registration; never stored in plaintext. */
  api_key: string;
}

export const listSensors = async (includeRevoked = false) =>
  (await api.get<SensorT[]>("/egress-sensor/sensors", { params: { include_revoked: includeRevoked } })).data;

export const registerSensor = async (name: string) =>
  (await api.post<SensorCreatedT>("/egress-sensor/sensors", { name })).data;

export const updateSensor = async (id: number, input: { name?: string; enabled?: boolean }) =>
  (await api.patch<SensorT>(`/egress-sensor/sensors/${id}`, input)).data;

export const revokeSensor = async (id: number) => {
  await api.delete(`/egress-sensor/sensors/${id}`);
};

/** Bump the org's policy revision so every sensor picks up the current
 *  policy on its next poll instead of waiting for the next scheduled
 *  change. Returns the new revision number. */
export const refreshSensor = async (id: number) =>
  (await api.post<{ bumped: boolean; new_revision: number }>(
    `/egress-sensor/sensors/${id}/refresh`,
  )).data;

// ---------------------------------------------------------------- workloads

export type RuntimeMode = "observe" | "alert" | "enforce";
export const RUNTIME_MODES: RuntimeMode[] = ["observe", "alert", "enforce"];

export type DNSMode = "off" | "listed" | "any";
export const DNS_MODES: DNSMode[] = ["off", "listed", "any"];

export type Protocol = "tcp" | "udp" | "icmp" | "";
export const PROTOCOLS: Protocol[] = ["tcp", "udp", "icmp"];

/** One allow rule: dest (egress) or source (ingress) can be a CIDR, an IP,
 *  or a host name (with "*.corp.internal" wildcards). Ports/protocols may be
 *  empty (any). */
export interface AllowT {
  dest?: string;
  source?: string;
  ports: number[];
  protocols: Protocol[];
}

export interface WorkloadT {
  id: number;
  org_id: number;
  agent_id: number | null;
  name: string;
  description: string | null;
  cgroup_patterns: string[];
  run_as_users: string[];
  egress_allow: AllowT[];
  ingress_allow: AllowT[];
  dns: DNSMode;
  mode: RuntimeMode;
  isolated: boolean;
  isolated_reason: string | null;
  enabled: boolean;
  deleted_at: string | null;
  created_at: string;
  updated_at: string | null;
}

export interface WorkloadInput {
  name: string;
  description?: string | null;
  agent_id: number | null;
  cgroup_patterns: string[];
  run_as_users: string[];
  egress_allow: AllowT[];
  ingress_allow: AllowT[];
  dns: DNSMode;
  mode: RuntimeMode;
  isolated: boolean;
  isolated_reason?: string | null;
  enabled: boolean;
}

export const listWorkloads = async (includeDeleted = false) =>
  (await api.get<WorkloadT[]>("/egress-sensor/workloads", { params: { include_deleted: includeDeleted } })).data;

export const createWorkload = async (input: WorkloadInput) =>
  (await api.post<WorkloadT>("/egress-sensor/workloads", input)).data;

export const updateWorkload = async (id: number, input: Partial<WorkloadInput>) =>
  (await api.patch<WorkloadT>(`/egress-sensor/workloads/${id}`, input)).data;

export const deleteWorkload = async (id: number) => {
  await api.delete(`/egress-sensor/workloads/${id}`);
};

// ---------------------------------------------------------------- violations

export type ViolationAction = "observed" | "alerted" | "blocked";
export const VIOLATION_ACTIONS: ViolationAction[] = ["observed", "alerted", "blocked"];

export interface ViolationT {
  id: number;
  sensor_id: number | null;
  workload_id: number | null;
  action: ViolationAction;
  kind: string;
  protocol: string | null;
  dst_ip: string | null;
  dst_port: number | null;
  dst_name: string | null;
  comm: string | null;
  cgroup: string | null;
  isolated: boolean;
  count: number;
  created_at: string;
}

export interface ViolationFilter {
  workload_id?: number;
  action?: ViolationAction;
  sensor_id?: number;
}

export const listViolations = async (filter: ViolationFilter = {}, limit = 200) =>
  (await api.get<ViolationT[]>("/egress-sensor/violations", { params: { ...filter, limit } })).data;

/** Violations from one sensor only — same shape, narrower query. */
export const listSensorViolations = async (id: number, limit = 100) =>
  (await api.get<ViolationT[]>(`/egress-sensor/sensors/${id}/violations`, { params: { limit } })).data;

// ---------------------------------------------------------------- per-workload snapshot

/** One row of a sensor's latest heartbeat: what the sensor governs under a
 *  workload, and how its DNS proxy is doing. */
export interface SensorWorkloadT {
  workload_id: number;
  workload_name: string;
  cgroups: number;
  processes: number;
  privileged: string[];
  dns_port: number | null;
  dns_total: number;
  dns_allowed: number;
  dns_denied: number;
  updated_at: string;
}

export const listSensorWorkloads = async (id: number) =>
  (await api.get<SensorWorkloadT[]>(`/egress-sensor/sensors/${id}/workloads`)).data;

// ---------------------------------------------------------------- policy settings

/** One row per organization: intervals the sensors poll and heartbeat at,
 *  and defaults for new workloads. */
export interface SensorSettingsT {
  refresh_seconds: number;
  heartbeat_seconds: number;
  default_mode: RuntimeMode;
  default_dns: DNSMode;
  updated_at: string | null;
}

export interface SensorSettingsInput {
  refresh_seconds?: number;
  heartbeat_seconds?: number;
  default_mode?: RuntimeMode;
  default_dns?: DNSMode;
}

export const getSensorSettings = async () =>
  (await api.get<SensorSettingsT>("/egress-sensor/settings")).data;

export const updateSensorSettings = async (input: SensorSettingsInput) =>
  (await api.patch<SensorSettingsT>("/egress-sensor/settings", input)).data;
