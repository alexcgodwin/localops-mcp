import { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import {
  certificateExpiry,
  certificateInventory,
  environmentVariablesSummary,
  installedSoftware,
  localAdmins,
  localGroups,
  localUsers,
  scheduledTasks,
  softwareChanges,
  softwareVersions,
  sshKeyInventory,
  startupPrograms
} from "./endpoint.js";

const readOnlyAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false
} as const;

function toolResult(payload: Record<string, unknown>) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }],
    structuredContent: payload
  };
}

const softwareSchema = z.object({
  name: z.string(),
  version: z.string().nullable(),
  publisher: z.string().nullable(),
  installDate: z.string().nullable(),
  source: z.string()
});

const userSchema = z.object({
  name: z.string(),
  enabled: z.boolean().optional(),
  lastLogon: z.string().nullable().optional(),
  passwordRequired: z.boolean().optional(),
  userMayChangePassword: z.boolean().optional(),
  uid: z.number().optional(),
  gid: z.number().optional(),
  home: z.string().optional(),
  shell: z.string().optional(),
  isSystemAccount: z.boolean().optional()
});

const groupSchema = z.object({
  name: z.string(),
  description: z.string().nullable().optional(),
  gid: z.number().optional(),
  members: z.array(z.string()).optional()
});

const adminSchema = z.object({
  name: z.string(),
  objectClass: z.string().nullable().optional(),
  principalSource: z.string().nullable().optional()
});

const startupSchema = z.object({
  name: z.string(),
  source: z.string(),
  user: z.string().nullable().optional(),
  state: z.string().optional()
});

const taskSchema = z.object({
  name: z.string(),
  path: z.string(),
  state: z.string(),
  author: z.string().nullable(),
  source: z.string()
});

const certificateSchema = z.object({
  store: z.string(),
  thumbprint: z.string(),
  subject: z.string(),
  issuer: z.string(),
  notBefore: z.string().nullable(),
  notAfter: z.string().nullable(),
  hasPrivateKey: z.boolean().nullable()
});

const sshKeySchema = z.object({
  name: z.string(),
  kind: z.string(),
  sizeBytes: z.number(),
  modifiedAt: z.string(),
  permissions: z.string().nullable()
});

export function registerEndpointInventoryTools(server: McpServer) {
  server.registerTool(
    "installed_software",
    {
      title: "Installed Software",
      description:
        "Return a bounded installed-software inventory with versions and publisher metadata. Windows reads uninstall registry metadata; Linux uses the available package database.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        limit: z.number().int().min(1).max(500).optional()
      }),
      outputSchema: z.object({
        packageManager: z.string(),
        packages: z.array(softwareSchema)
      })
    },
    async ({ limit }) => toolResult(await installedSoftware(limit))
  );

  server.registerTool(
    "software_versions",
    {
      title: "Software Versions",
      description:
        "Look up installed versions for up to 50 requested software names without launching or modifying the software.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        names: z.array(z.string().min(1).max(200)).min(1).max(50)
      }),
      outputSchema: z.object({
        requested: z.array(z.string()),
        matches: z.array(softwareSchema),
        packageManager: z.string()
      })
    },
    async ({ names }) => toolResult(await softwareVersions(names))
  );

  server.registerTool(
    "software_changes",
    {
      title: "Software Changes",
      description:
        "Compare the current bounded installed-software inventory with a caller-supplied baseline. The server does not persist a baseline or write to disk.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        previousInventory: z.array(z.object({
          name: z.string().min(1).max(300),
          version: z.string().max(300).nullable().optional()
        })).max(500)
      }),
      outputSchema: z.object({
        baselineCount: z.number(),
        currentCount: z.number(),
        added: z.array(softwareSchema),
        removed: z.array(z.object({
          name: z.string(),
          version: z.string().nullable()
        })),
        versionChanged: z.array(z.object({
          name: z.string(),
          previousVersion: z.string().nullable(),
          currentVersion: z.string().nullable()
        })),
        limitation: z.string()
      })
    },
    async ({ previousInventory }) =>
      toolResult(await softwareChanges(previousInventory))
  );

  server.registerTool(
    "local_users",
    {
      title: "Local Users",
      description:
        "Return bounded local account metadata. Passwords, password hashes and credential material are never returned.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        limit: z.number().int().min(1).max(300).optional()
      }),
      outputSchema: z.object({ users: z.array(userSchema) })
    },
    async ({ limit }) => toolResult({ users: await localUsers(limit) })
  );

  server.registerTool(
    "local_groups",
    {
      title: "Local Groups",
      description:
        "Return bounded local group metadata and Linux group membership where available.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        limit: z.number().int().min(1).max(300).optional()
      }),
      outputSchema: z.object({ groups: z.array(groupSchema) })
    },
    async ({ limit }) => toolResult({ groups: await localGroups(limit) })
  );

  server.registerTool(
    "local_admins",
    {
      title: "Local Administrators",
      description:
        "Identify members of the built-in Windows Administrators group or common Linux administrative groups without modifying membership.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({}),
      outputSchema: z.object({ administrators: z.array(adminSchema) })
    },
    async () => toolResult({ administrators: await localAdmins() })
  );

  server.registerTool(
    "startup_programs",
    {
      title: "Startup Programs",
      description:
        "Inventory Windows startup registrations or enabled Linux systemd/XDG startup entries. Startup command lines are intentionally not returned.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        limit: z.number().int().min(1).max(300).optional()
      }),
      outputSchema: z.object({ startupPrograms: z.array(startupSchema) })
    },
    async ({ limit }) =>
      toolResult({ startupPrograms: await startupPrograms(limit) })
  );

  server.registerTool(
    "scheduled_tasks",
    {
      title: "Scheduled Tasks",
      description:
        "Inventory Windows scheduled tasks or Linux systemd timers and cron directory entries without returning task action commands.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        limit: z.number().int().min(1).max(300).optional()
      }),
      outputSchema: z.object({ tasks: z.array(taskSchema) })
    },
    async ({ limit }) => toolResult({ tasks: await scheduledTasks(limit) })
  );

  server.registerTool(
    "certificate_inventory",
    {
      title: "Certificate Inventory",
      description:
        "Inventory bounded certificate metadata and expiry dates. Private key material is never read or returned.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        limit: z.number().int().min(1).max(300).optional()
      }),
      outputSchema: z.object({ certificates: z.array(certificateSchema) })
    },
    async ({ limit }) =>
      toolResult({ certificates: await certificateInventory(limit) })
  );

  server.registerTool(
    "certificate_expiry",
    {
      title: "Certificate Expiry",
      description:
        "Return certificates already expired or expiring within the requested window.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        withinDays: z.number().int().min(0).max(3650).optional(),
        limit: z.number().int().min(1).max(300).optional()
      }),
      outputSchema: z.object({
        certificates: z.array(certificateSchema.extend({
          daysUntilExpiry: z.number()
        }))
      })
    },
    async ({ withinDays, limit }) =>
      toolResult({ certificates: await certificateExpiry(withinDays, limit) })
  );

  server.registerTool(
    "ssh_key_inventory",
    {
      title: "SSH Key Inventory",
      description:
        "List metadata for files in the current user's SSH directory. Key contents, private key material and authorized key contents are never read or returned.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        limit: z.number().int().min(1).max(200).optional()
      }),
      outputSchema: z.object({
        directory: z.string(),
        keys: z.array(sshKeySchema)
      })
    },
    async ({ limit }) => toolResult(await sshKeyInventory(limit))
  );

  server.registerTool(
    "environment_variables_summary",
    {
      title: "Environment Variables Summary",
      description:
        "Return environment-variable names and a sensitive-name flag only. Values are never exposed.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        limit: z.number().int().min(1).max(300).optional()
      }),
      outputSchema: z.object({
        variableCount: z.number(),
        returnedCount: z.number(),
        valuesExposed: z.boolean(),
        variables: z.array(z.object({
          name: z.string(),
          present: z.boolean(),
          sensitiveName: z.boolean()
        }))
      })
    },
    async ({ limit }) => toolResult(environmentVariablesSummary(limit))
  );
}
