import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: { 'Content-Type': 'application/json' },
});

export const getStatus        = ()                  => api.get('/status');
export const getAlerts        = (limit = 50)        => api.get('/alerts',        { params: { limit } });
export const getActions       = (limit = 50)        => api.get('/actions',       { params: { limit } });
export const getVerifications = (limit = 50)        => api.get('/verifications', { params: { limit } });
export const getRisk          = ()                  => api.get('/risk');
export const getHistory       = (limit = 100)       => api.get('/history',       { params: { limit } });
export const getStats         = ()                  => api.get('/stats');
export const getBlocked       = ()                  => api.get('/blocked');
export const getTraffic       = ()                  => api.get('/traffic');

export const startMonitor  = (window_seconds = 10, interval_seconds = 2) =>
  api.post('/monitor/start', { window_seconds, interval_seconds });
export const stopMonitor   = ()   => api.post('/monitor/stop');
export const resetScan     = ()   => api.post('/scan/reset');
export const unblockIp     = (ip) => api.post('/unblock', { ip });

export default api;