import { api } from '../api/client';

// Thin accessor so components import the typed client through a hook, per
// the Phase 8 structure. The client itself (api/client.ts) owns the Axios
// instance, base URL (VITE_API_URL), and 404→null / 500→throw handling.
export function useApi() {
  return api;
}
