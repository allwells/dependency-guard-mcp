// HTTP server — Express with /health endpoint.
// MCP tool registration is added in Phase 4.

import express from 'express';
import { logger } from './utils/logger.js';

const PORT = parseInt(process.env['PORT'] ?? '8000', 10);

export function startServer(): void {
  const app = express();

  app.use(express.json());

  // Health check — used by CTX Protocol uptime monitoring
  app.get('/health', (_req, res) => {
    res.json({
      status: 'OK',
      service: 'DependencyGuard MCP',
      version: process.env['npm_package_version'] ?? '1.0.0',
    });
  });

  app.listen(PORT, () => {
    logger.info('server', `DependencyGuard MCP listening on port ${PORT}`);
  });
}
