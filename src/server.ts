// HTTP server — Express with /health and /mcp endpoints.

import express from "express";
import type { RequestHandler } from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { createContextMiddleware } from "@ctxprotocol/sdk";
import { createMcpServer } from "./mcp.js";
import { logger } from "./utils/logger.js";

const PORT = parseInt(process.env["PORT"] ?? "8000", 10);

export function startServer(): void {
  const app = express();

  app.use(express.json());

  // Health check — used by CTX Protocol uptime monitoring
  app.get("/health", (_req, res) => {
    res.json({
      status: "OK",
      service: "DependencyGuard MCP",
      version: process.env["npm_package_version"] ?? "1.0.0",
    });
  });

  // CTX Protocol auth middleware — allows discovery (tools/list) without auth,
  // requires verified JWT for execution (tools/call)
  app.use("/mcp", createContextMiddleware() as unknown as RequestHandler);

  // MCP endpoint — stateless HTTP Streaming transport (one server+transport per request).
  // No-arg constructor omits sessionIdGenerator, which is stateless mode at runtime.
  // Cast to Transport required: SDK optional property types conflict with exactOptionalPropertyTypes.
  app.post("/mcp", async (req, res) => {
    const server = createMcpServer();
    const transport = new StreamableHTTPServerTransport();
    await server.connect(transport as Transport);
    await transport.handleRequest(req, res, req.body);
    res.on("finish", () => server.close());
  });

  app.listen(PORT, () => {
    logger.info("server", `DependencyGuard MCP listening on port ${PORT}`);
    logger.info("server", `MCP endpoint: http://localhost:${PORT}/mcp`);
  });
}
