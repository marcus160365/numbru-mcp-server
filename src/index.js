import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createMcpHandler } from "agents/mcp";
import { z } from "zod";

// ---------------------------------------------------------------------------
// OAuth 2.1 helpers
// ---------------------------------------------------------------------------

function generateId(len = 32) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Base64url(plain) {
  const data = new TextEncoder().encode(plain);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function baseUrl(request) {
  const url = new URL(request.url);
  return `${url.protocol}//${url.host}`;
}

// ---------------------------------------------------------------------------
// OAuth endpoint handlers
// ---------------------------------------------------------------------------

async function handleOAuthMetadata(request) {
  const base = baseUrl(request);
  return Response.json({
    issuer: base,
    authorization_endpoint: `${base}/authorize`,
    token_endpoint: `${base}/token`,
    registration_endpoint: `${base}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["none"],
    code_challenge_methods_supported: ["S256"],
  });
}

async function handleRegister(request, env) {
  const body = await request.json();
  const clientId = `mcp_${generateId(16)}`;

  await env.OAUTH_STATE.put(
    `client:${clientId}`,
    JSON.stringify({
      client_id: clientId,
      redirect_uris: body.redirect_uris || [],
      client_name: body.client_name || "MCP Client",
      created_at: Date.now(),
    }),
    { expirationTtl: 86400 * 30 } // 30 days
  );

  return Response.json({
    client_id: clientId,
    redirect_uris: body.redirect_uris || [],
    client_name: body.client_name || "MCP Client",
    token_endpoint_auth_method: "none",
  }, { status: 201 });
}

async function handleAuthorize(request, env) {
  const url = new URL(request.url);
  const clientId = url.searchParams.get("client_id");
  const redirectUri = url.searchParams.get("redirect_uri");
  const state = url.searchParams.get("state");
  const codeChallenge = url.searchParams.get("code_challenge");
  const codeChallengeMethod = url.searchParams.get("code_challenge_method");

  if (!clientId || !redirectUri || !codeChallenge) {
    return Response.json({ error: "invalid_request", error_description: "Missing required parameters" }, { status: 400 });
  }

  // Verify registered client
  const clientData = await env.OAUTH_STATE.get(`client:${clientId}`);
  if (!clientData) {
    return Response.json({ error: "invalid_client" }, { status: 400 });
  }

  // Store the OAuth session state
  const sessionId = generateId(16);
  await env.OAUTH_STATE.put(
    `session:${sessionId}`,
    JSON.stringify({
      client_id: clientId,
      redirect_uri: redirectUri,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: codeChallengeMethod || "S256",
    }),
    { expirationTtl: 600 } // 10 min
  );

  // Build WorkOS authorization URL
  const workosAuthUrl = new URL("https://api.workos.com/user_management/authorize");
  workosAuthUrl.searchParams.set("client_id", env.WORKOS_CLIENT_ID);
  workosAuthUrl.searchParams.set("redirect_uri", `${baseUrl(request)}/callback`);
  workosAuthUrl.searchParams.set("response_type", "code");
  workosAuthUrl.searchParams.set("state", sessionId);
  workosAuthUrl.searchParams.set("provider", "authkit");

  return Response.redirect(workosAuthUrl.toString(), 302);
}

async function handleCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const sessionId = url.searchParams.get("state");

  if (!code || !sessionId) {
    return Response.json({ error: "invalid_request" }, { status: 400 });
  }

  // Retrieve session
  const sessionData = await env.OAUTH_STATE.get(`session:${sessionId}`);
  if (!sessionData) {
    return Response.json({ error: "invalid_session", error_description: "Session expired or not found" }, { status: 400 });
  }
  const session = JSON.parse(sessionData);

  // Exchange code with WorkOS for tokens
  const tokenRes = await fetch("https://api.workos.com/user_management/authenticate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: env.WORKOS_CLIENT_ID,
      client_secret: env.WORKOS_API_KEY,
      grant_type: "authorization_code",
      code,
    }),
  });

  if (!tokenRes.ok) {
    const err = await tokenRes.text();
    console.error("WorkOS token exchange failed:", err);
    return Response.json({ error: "upstream_auth_failed" }, { status: 502 });
  }

  const workosTokens = await tokenRes.json();

  // Generate our own authorization code for the MCP client
  const mcpCode = generateId(32);
  await env.OAUTH_STATE.put(
    `code:${mcpCode}`,
    JSON.stringify({
      client_id: session.client_id,
      code_challenge: session.code_challenge,
      code_challenge_method: session.code_challenge_method,
      access_token: workosTokens.access_token,
      refresh_token: workosTokens.refresh_token,
    }),
    { expirationTtl: 300 } // 5 min
  );

  // Clean up session
  await env.OAUTH_STATE.delete(`session:${sessionId}`);

  // Redirect back to MCP client with our auth code
  const redirectUrl = new URL(session.redirect_uri);
  redirectUrl.searchParams.set("code", mcpCode);
  if (session.state) redirectUrl.searchParams.set("state", session.state);

  return Response.redirect(redirectUrl.toString(), 302);
}

async function handleToken(request, env) {
  let body;
  const contentType = request.headers.get("Content-Type") || "";
  if (contentType.includes("application/json")) {
    body = await request.json();
  } else {
    body = Object.fromEntries(new URLSearchParams(await request.text()));
  }

  const { grant_type, code, code_verifier, refresh_token, client_id } = body;

  if (grant_type === "authorization_code") {
    if (!code || !code_verifier) {
      return Response.json({ error: "invalid_request", error_description: "Missing code or code_verifier" }, { status: 400 });
    }

    const codeData = await env.OAUTH_STATE.get(`code:${code}`);
    if (!codeData) {
      return Response.json({ error: "invalid_grant", error_description: "Code expired or not found" }, { status: 400 });
    }
    const stored = JSON.parse(codeData);

    // Verify PKCE
    const computedChallenge = await sha256Base64url(code_verifier);
    if (computedChallenge !== stored.code_challenge) {
      return Response.json({ error: "invalid_grant", error_description: "PKCE verification failed" }, { status: 400 });
    }

    // Clean up used code
    await env.OAUTH_STATE.delete(`code:${code}`);

    // Store refresh token mapping
    const refreshId = generateId(32);
    await env.OAUTH_STATE.put(
      `refresh:${refreshId}`,
      JSON.stringify({
        client_id: stored.client_id,
        workos_refresh_token: stored.refresh_token,
      }),
      { expirationTtl: 86400 * 7 } // 7 days
    );

    return Response.json({
      access_token: stored.access_token,
      token_type: "Bearer",
      expires_in: 300,
      refresh_token: refreshId,
    });
  }

  if (grant_type === "refresh_token") {
    if (!refresh_token) {
      return Response.json({ error: "invalid_request" }, { status: 400 });
    }

    const refreshData = await env.OAUTH_STATE.get(`refresh:${refresh_token}`);
    if (!refreshData) {
      return Response.json({ error: "invalid_grant", error_description: "Refresh token expired" }, { status: 400 });
    }
    const stored = JSON.parse(refreshData);

    // Exchange with WorkOS for new tokens
    const tokenRes = await fetch("https://api.workos.com/user_management/authenticate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: env.WORKOS_CLIENT_ID,
        client_secret: env.WORKOS_API_KEY,
        grant_type: "refresh_token",
        refresh_token: stored.workos_refresh_token,
      }),
    });

    if (!tokenRes.ok) {
      await env.OAUTH_STATE.delete(`refresh:${refresh_token}`);
      return Response.json({ error: "invalid_grant", error_description: "WorkOS refresh failed" }, { status: 400 });
    }

    const newTokens = await tokenRes.json();

    // Update refresh token mapping
    const newRefreshId = generateId(32);
    await env.OAUTH_STATE.put(
      `refresh:${newRefreshId}`,
      JSON.stringify({
        client_id: stored.client_id,
        workos_refresh_token: newTokens.refresh_token,
      }),
      { expirationTtl: 86400 * 7 }
    );

    // Delete old refresh token
    await env.OAUTH_STATE.delete(`refresh:${refresh_token}`);

    return Response.json({
      access_token: newTokens.access_token,
      token_type: "Bearer",
      expires_in: 300,
      refresh_token: newRefreshId,
    });
  }

  return Response.json({ error: "unsupported_grant_type" }, { status: 400 });
}

// ---------------------------------------------------------------------------
// MCP tool definitions
// ---------------------------------------------------------------------------

function createServer(env, authToken) {
  const api = env.NUMBRU_API;
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

  // --- Complete Profile ---
  server.registerTool(
    "complete_profile",
    {
      title: "Complete Profile",
      description:
        "Complete the user's profile (one-time signup). Sets name, profession, and generates a User Compass. Required before creating clients.",
      inputSchema: {
        first_name: z.string().min(1).describe("First name (required)"),
        last_name: z.string().min(1).describe("Last name (required)"),
        profession: z.enum(["real_estate", "design", "hospitality_travel", "event_planning"]).describe("Profession (required)"),
        middle_name: z.string().optional().describe("Middle name (optional)"),
        maiden_name: z.string().optional().describe("Maiden/birth name (optional)"),
        phone: z.string().optional().describe("Phone number (optional)"),
        dob: z.string().optional().describe("Date of birth YYYY-MM-DD (optional, improves compass)"),
      },
    },
    async ({ first_name, last_name, profession, middle_name, maiden_name, phone, dob }) => {
      const body = { first_name, last_name, profession };
      if (middle_name) body.middle_name = middle_name;
      if (maiden_name) body.maiden_name = maiden_name;
      if (phone) body.phone = phone;
      if (dob) body.dob = dob;

      const res = await api.fetch("https://dummy/me/profile", {
        method: "POST",
        headers,
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) {
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }], isError: true };
      }
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }
  );

  // --- Update Profile ---
  server.registerTool(
    "update_profile",
    {
      title: "Update Profile",
      description:
        "Update the user's profile settings. Can change name, profession, phone, DOB, or custom prompt.",
      inputSchema: {
        first_name: z.string().optional().describe("First name"),
        last_name: z.string().optional().describe("Last name"),
        profession: z.enum(["real_estate", "design", "hospitality_travel", "event_planning"]).optional().describe("Profession"),
        middle_name: z.string().optional().describe("Middle name"),
        maiden_name: z.string().optional().describe("Maiden/birth name"),
        phone: z.string().optional().describe("Phone number"),
        dob: z.string().optional().describe("Date of birth YYYY-MM-DD"),
        custom_prompt: z.string().optional().describe("Custom instructions for AI interactions"),
      },
    },
    async ({ first_name, last_name, profession, middle_name, maiden_name, phone, dob, custom_prompt }) => {
      const body = {};
      if (first_name !== undefined) body.first_name = first_name;
      if (last_name !== undefined) body.last_name = last_name;
      if (profession !== undefined) body.profession = profession;
      if (middle_name !== undefined) body.middle_name = middle_name;
      if (maiden_name !== undefined) body.maiden_name = maiden_name;
      if (phone !== undefined) body.phone = phone;
      if (dob !== undefined) body.dob = dob;
      if (custom_prompt !== undefined) body.custom_prompt = custom_prompt;

      const res = await api.fetch("https://dummy/me/profile", {
        method: "PUT",
        headers,
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) {
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }], isError: true };
      }
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }
  );

  // --- Generate Compass ---
  server.registerTool(
    "generate_compass",
    {
      title: "Generate Compass",
      description:
        "Generate a numbrU Compass profile for a person using the Compass engine. Returns personality insights, communication style, and relationship strategies.",
      inputSchema: {
        name: z.string().min(1).describe("Full name of the person"),
        dob: z.string().describe("Date of birth in YYYY-MM-DD format"),
        vertical: z
          .enum(["real_estate", "sales", "civic", "insurance"])
          .default("real_estate")
          .describe("Industry vertical (default: real_estate)"),
      },
    },
    async ({ name, dob, vertical }) => {
      const res = await env.COMPASS_ENGINE.fetch("https://dummy/compass", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(authToken ? { Authorization: authToken } : {}),
        },
        body: JSON.stringify({ vertical, payload: { full_name: name, dob } }),
      });

      if (!res.ok) {
        const errText = await res.text();
        return {
          content: [{ type: "text", text: `Compass engine error (${res.status}): ${errText}` }],
          isError: true,
        };
      }

      const data = await res.json();
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }
  );

  return server;
}

// ---------------------------------------------------------------------------
// Main fetch handler — routes OAuth endpoints, then MCP
// ---------------------------------------------------------------------------

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      });
    }

    // --- OAuth 2.1 endpoints ---
    if (path === "/.well-known/oauth-authorization-server") {
      return handleOAuthMetadata(request);
    }
    if (path === "/register" && request.method === "POST") {
      return handleRegister(request, env);
    }
    if (path === "/authorize" && request.method === "GET") {
      return handleAuthorize(request, env);
    }
    if (path === "/callback" && request.method === "GET") {
      return handleCallback(request, env);
    }
    if (path === "/token" && request.method === "POST") {
      return handleToken(request, env);
    }

    // --- MCP handler (everything else) ---
    const authToken = request.headers.get("Authorization");
    const server = createServer(env, authToken);
    return createMcpHandler(server, { route: "/" })(request, env, ctx);
  },
};
