// MCP server — registers the check_cve tool and handles protocol transport

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { runVerdict } from './tools/verdict.js';
import { logger } from './utils/logger.js';

const CVE_ID_PATTERN = /^CVE-\d{4}-\d{4,}$/i;

export async function startMcp(): Promise<void> {
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
    },
    async ({ cve_id }) => {
      const normalizedId = cve_id.toUpperCase();
      logger.info('mcp', 'Tool call received', { cve_id: normalizedId });

      const result = await runVerdict(normalizedId);

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(result),
          },
        ],
      };
    },
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);

  logger.info('mcp', 'DependencyGuard MCP server connected via stdio');
}
