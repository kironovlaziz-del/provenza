// Egress sensor: hosts running the provenza-sensor daemon, their heartbeat,
// and the violations they reported.
// Backend: app/api/egress_sensor.py, /api/v1/egress-sensor.
//
// The admin side uses the same JWT as the rest of the product; the sensor
// side (GET /config, POST /heartbeat, POST /violations) is not reached from
// the browser and lives in the daemon under sensor/.
import { api } from "./api";

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

export type SensorViolationAction = "observed" | "alerted" | "blocked";

export interface SensorViolationT {
  id: number;
  sensor_id: number | null;
  workload_id: number | null;
  action: SensorViolationAction;
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

export const listSensors = async (includeRevoked = false) =>
  (await api.get<SensorT[]>("/egress-sensor/sensors", { params: { include_revoked: includeRevoked } })).data;

export const registerSensor = async (name: string) =>
  (await api.post<SensorCreatedT>("/egress-sensor/sensors", { name })).data;

export const updateSensor = async (id: number, input: { name?: string; enabled?: boolean }) =>
  (await api.patch<SensorT>(`/egress-sensor/sensors/${id}`, input)).data;

export const revokeSensor = async (id: number) => {
  await api.delete(`/egress-sensor/sensors/${id}`);
};

export const listSensorViolations = async (id: number, limit = 100) =>
  (await api.get<SensorViolationT[]>(`/egress-sensor/sensors/${id}/violations`, { params: { limit } })).data;
