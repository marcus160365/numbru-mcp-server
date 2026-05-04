import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createMcpHandler } from "agents/mcp";
import { z } from "zod";

function createServer(env, authToken) {
  const api = env.NUMBRU_API; // Service binding to numbru-api worker
  const headers = authToken
    ? { "Content-Type": "application/json", Authorization: authToken }
    : { "Content-Type": "application/json" };

  const server = new McpServer({
    name: "numbrU API",
    version: "1.0.0",
  });

  // --- Health Check ---
  server.registerTool(
    "health_check",
    {
      title: "Health Check",
      description: "Check the health status of the numbrU API",
      inputSchema: {},
    },
    async () => {
      const res = await api.fetch("https://dummy/health");
      const data = await res.json();
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }
  );

  // --- List People ---
  server.registerTool(
    "list_people",
    {
      title: "List People",
      description:
        "Retrieve all people (clients) for the authenticated user. Optionally search by name.",
      inputSchema: {
        search: z
          .string()
          .optional()
          .describe("Search by name (partial match, case-insensitive)"),
      },
    },
    async ({ search }) => {
      const params = new URLSearchParams();
      if (search) params.set("search", search);
      const url = `https://dummy/people${params.toString() ? "?" + params : ""}`;
      const res = await api.fetch(url, { headers });
      const data = await res.json();
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }
  );

  // --- Get Person ---
  server.registerTool(
    "get_person",
    {
      title: "Get Person",
      description:
        "Retrieve a single person (client) by their ID, including their Client Compass data.",
      inputSchema: {
        person_id: z.string().describe("The UUID of the person to retrieve"),
      },
    },
    async ({ person_id }) => {
      const res = await api.fetch(`https://dummy/people/${person_id}`, { headers });
      if (res.status === 404) {
        return {
          content: [{ type: "text", text: `Person with ID ${person_id} not found.` }],
          isError: true,
        };
      }
      const data = await res.json();
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }
  );

  // --- Create Person ---
  server.registerTool(
    "create_person",
    {
      title: "Create Person",
      description:
        "Create a new person (client). Generates their Client Compass automatically. Requires the user to have a profession set.",
      inputSchema: {
        first_name: z.string().min(1).max(200).describe("First name (required)"),
        middle_name: z.string().max(200).optional().describe("Middle name (optional)"),
        last_name: z.string().min(1).max(200).describe("Last name (required)"),
        dob: z
          .string()
          .optional()
          .describe("Date of birth in YYYY-MM-DD format (optional, improves compass accuracy)"),
        key_parties: z
          .array(
            z.object({
              id: z.enum(["spouse_partner", "parent", "colleague", "friend", "investor"]),
              name: z.string().optional(),
            })
          )
          .optional()
          .describe("Key parties involved (e.g. spouse, parent, colleague)"),
        must_haves_avoids: z
          .string()
          .max(2000)
          .optional()
          .describe("Notes on must-haves or things to avoid"),
        is_first_interaction: z
          .boolean()
          .optional()
          .describe("Is this the first interaction with this client? Default: true"),
      },
    },
    async ({ first_name, middle_name, last_name, dob, key_parties, must_haves_avoids, is_first_interaction }) => {
      const body = { first_name, last_name };
      if (middle_name !== undefined) body.middle_name = middle_name;
      if (dob !== undefined) body.dob = dob;
      if (key_parties !== undefined) body.key_parties = key_parties;
      if (must_haves_avoids !== undefined) body.must_haves_avoids = must_haves_avoids;
      if (is_first_interaction !== undefined) body.is_first_interaction = is_first_interaction;

      const res = await api.fetch("https://dummy/people", {
        method: "POST",
        headers,
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) {
        return {
          content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
          isError: true,
        };
      }
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }
  );

  // --- Get Chat Messages ---
  server.registerTool(
    "get_chat_messages",
    {
      title: "Get Chat Messages",
      description:
        "Retrieve chat message history for a specific person (client). Returns messages in reverse chronological order.",
      inputSchema: {
        person_id: z.string().describe("The UUID of the person"),
        limit: z
          .number()
          .int()
          .min(1)
          .max(100)
          .optional()
          .describe("Max messages to return (default: 50)"),
        cursor: z
          .string()
          .optional()
          .describe("Pagination cursor from a previous response"),
      },
    },
    async ({ person_id, limit, cursor }) => {
      const params = new URLSearchParams();
      if (limit !== undefined) params.set("limit", String(limit));
      if (cursor) params.set("cursor", cursor);
      const url = `https://dummy/people/${person_id}/chat/messages${params.toString() ? "?" + params : ""}`;
      const res = await api.fetch(url, { headers });
      const data = await res.json();
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }
  );

  // --- Send Chat Message ---
  server.registerTool(
    "send_chat_message",
    {
      title: "Send Chat Message",
      description:
        "Send a chat message about a specific person (client). The AI will respond with tailored advice based on the client's Compass profile.",
      inputSchema: {
        person_id: z.string().describe("The UUID of the person"),
        message: z.string().min(1).describe("The message to send"),
      },
    },
    async ({ person_id, message }) => {
      const res = await api.fetch(`https://dummy/people/${person_id}/chat`, {
        method: "POST",
        headers,
        body: JSON.stringify({ message }),
      });
      const data = await res.json();
      if (!res.ok) {
        return {
          content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
          isError: true,
        };
      }
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }
  );

  // --- Get Current User ---
  server.registerTool(
    "get_me",
    {
      title: "Get Current User",
      description: "Retrieve the authenticated user's profile information.",
      inputSchema: {},
    },
    async () => {
      const res = await api.fetch("https://dummy/me", { headers });
      const data = await res.json();
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }
  );

  return server;
}

export default {
  fetch(request, env, ctx) {
    const authToken = request.headers.get("Authorization");
    const server = createServer(env, authToken);
    return createMcpHandler(server, { route: "/" })(request, env, ctx);
  },
};
