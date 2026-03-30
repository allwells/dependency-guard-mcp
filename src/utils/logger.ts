// Structured stderr logger — stdout is reserved for MCP protocol messages

type LogLevel = "info" | "warn" | "error";

function log(
  level: LogLevel,
  source: string,
  message: string,
  context?: Record<string, unknown>,
): void {
  const entry = JSON.stringify({
    timestamp: new Date().toISOString(),
    level,
    source,
    message,
    ...(context !== undefined ? { context } : {}),
  });
  process.stderr.write(entry + "\n");
}

export const logger = {
  info: (source: string, message: string, context?: Record<string, unknown>) =>
    log("info", source, message, context),
  warn: (source: string, message: string, context?: Record<string, unknown>) =>
    log("warn", source, message, context),
  error: (source: string, message: string, context?: Record<string, unknown>) =>
    log("error", source, message, context),
};
