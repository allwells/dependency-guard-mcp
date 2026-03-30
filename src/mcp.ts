// MCP server — registers the check_cve tool and returns a configured McpServer

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { runVerdict } from './tools/verdict.js';
import { logger } from './utils/logger.js';

const CVE_ID_PATTERN = /^CVE-\d{4}-\d{4,}$/i;

const nvdResultSchema = z.object({
  cve_id: z.string(),
  cvss_score: z.number().nullable(),
  cvss_severity: z.string().nullable(),
  description: z.string().nullable(),
  published: z.string().nullable(),
  last_modified: z.string().nullable(),
});

const cisaResultSchema = z.object({
  cve_id: z.string(),
  in_kev: z.boolean(),
  date_added: z.string().nullable(),
  due_date: z.string().nullable(),
  vendor_project: z.string().nullable(),
  product: z.string().nullable(),
  required_action: z.string().nullable(),
});

const epssResultSchema = z.object({
  cve_id: z.string(),
  epss_score: z.number().nullable(),
  percentile: z.number().nullable(),
  date: z.string().nullable(),
});

const verdictResultSchema = z.object({
  cve_id: z.string(),
  verdict: z.enum(['EXPLOIT_ACTIVE', 'HIGH_RISK', 'ELEVATED_RISK', 'LOW_RISK']),
  confidence: z.enum(['full', 'partial', 'stale']),
  cvss_score: z.number().nullable(),
  epss_score: z.number().nullable(),
  in_kev: z.boolean(),
  description: z.string().nullable(),
  recommended_action: z.string(),
  sources: z.object({
    nvd: nvdResultSchema.nullable(),
    cisa: cisaResultSchema.nullable(),
    epss: epssResultSchema.nullable(),
  }),
});

export function createMcpServer(): McpServer {
  const server = new McpServer({
    name: 'dependency-guard',
    version: process.env['npm_package_version'] ?? '1.0.0',
  });

  server.registerTool(
    'check_cve',
    {
      title: 'Check CVE Risk',
      description:
        'Returns a prioritized risk verdict for a CVE by combining NIST NVD (CVSS score), CISA KEV (active exploitation), and FIRST EPSS (exploit probability) data.',
      inputSchema: {
        cve_id: z
          .string()
          .regex(CVE_ID_PATTERN, 'Must be a valid CVE ID (e.g. CVE-2021-44228)'),
      },
      outputSchema: verdictResultSchema,
    },
    async ({ cve_id }) => {
      const normalizedId = cve_id.toUpperCase();
      logger.info('mcp', 'Tool call received', { cve_id: normalizedId });

      const result = await runVerdict(normalizedId);

      return {
        structuredContent: result as unknown as Record<string, unknown>,
        content: [{ type: 'text', text: JSON.stringify(result) }],
      };
    },
  );

  return server;
}
