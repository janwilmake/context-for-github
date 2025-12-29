/// <reference types="@cloudflare/workers-types" />
import { DurableObject } from "cloudflare:workers";
import Stripe from "stripe";

export interface Env {
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  STRIPE_PAYMENT_LINK: string;
  STRIPE_PAYMENT_LINK_ID: string;
  STRIPE_SECRET: string;
  STRIPE_WEBHOOK_SIGNING_SECRET: string;
  SubscriptionDO: DurableObjectNamespace<SubscriptionDO>;
}

const DO_NAME = "global";

// ============================================================================
// GitHub OAuth Middleware
// ============================================================================

interface OAuthState {
  redirectTo?: string;
  codeVerifier: string;
}

interface SessionData {
  user: {
    login: string;
    id: number;
    avatar_url: string;
    email?: string;
  };
  accessToken: string;
  exp: number;
}

function parseCookies(cookieHeader: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  cookieHeader.split(";").forEach((cookie) => {
    const [name, value] = cookie.trim().split("=");
    if (name && value) {
      cookies[name] = decodeURIComponent(value);
    }
  });
  return cookies;
}

function getCurrentUser(request: Request): SessionData["user"] | null {
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const sessionToken = cookies.session;
  if (!sessionToken) return null;

  try {
    const sessionData: SessionData = JSON.parse(atob(sessionToken));
    if (Date.now() > sessionData.exp) return null;
    return sessionData.user;
  } catch {
    return null;
  }
}

function getAccessToken(request: Request): string | null {
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const sessionToken = cookies.session;
  if (!sessionToken) return null;

  try {
    const sessionData: SessionData = JSON.parse(atob(sessionToken));
    if (Date.now() > sessionData.exp) return null;
    return sessionData.accessToken;
  } catch {
    return null;
  }
}

function generateCodeVerifier(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...Array.from(array)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return btoa(String.fromCharCode(...Array.from(new Uint8Array(digest))))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

async function handleLogin(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const redirectTo = url.searchParams.get("redirect_to") || "/";

  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);

  const state: OAuthState = { redirectTo, codeVerifier };
  const stateString = btoa(JSON.stringify(state));

  const githubUrl = new URL("https://github.com/login/oauth/authorize");
  githubUrl.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
  githubUrl.searchParams.set("redirect_uri", `${url.origin}/callback`);
  githubUrl.searchParams.set("scope", "user:email repo");
  githubUrl.searchParams.set("state", stateString);
  githubUrl.searchParams.set("code_challenge", codeChallenge);
  githubUrl.searchParams.set("code_challenge_method", "S256");

  return new Response(null, {
    status: 302,
    headers: {
      Location: githubUrl.toString(),
      "Set-Cookie": `oauth_state=${encodeURIComponent(
        stateString,
      )}; HttpOnly; Secure; SameSite=Lax; Max-Age=600; Path=/`,
    },
  });
}

async function handleCallback(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const stateParam = url.searchParams.get("state");

  if (!code || !stateParam) {
    return new Response("Missing code or state parameter", { status: 400 });
  }

  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const stateCookie = cookies.oauth_state;

  if (!stateCookie || stateCookie !== stateParam) {
    return new Response("Invalid state parameter", { status: 400 });
  }

  let state: OAuthState;
  try {
    state = JSON.parse(atob(stateParam));
  } catch {
    return new Response("Invalid state format", { status: 400 });
  }

  const tokenResponse = await fetch(
    "https://github.com/login/oauth/access_token",
    {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        client_id: env.GITHUB_CLIENT_ID,
        client_secret: env.GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: `${url.origin}/callback`,
        code_verifier: state.codeVerifier,
      }),
    },
  );

  const tokenData: any = await tokenResponse.json();
  if (!tokenData.access_token) {
    return new Response("Failed to get access token", { status: 400 });
  }

  const userResponse = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${tokenData.access_token}`,
      Accept: "application/vnd.github.v3+json",
      "User-Agent": "Context-Subscription",
    },
  });

  if (!userResponse.ok) {
    return new Response("Failed to get user info", { status: 400 });
  }

  const userData: any = await userResponse.json();

  const sessionData: SessionData = {
    user: {
      login: userData.login,
      id: userData.id,
      avatar_url: userData.avatar_url,
      email: userData.email,
    },
    accessToken: tokenData.access_token,
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000,
  };

  const sessionToken = btoa(JSON.stringify(sessionData));
  const headers = new Headers({ Location: state.redirectTo || "/" });
  headers.append(
    "Set-Cookie",
    "oauth_state=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/",
  );
  headers.append(
    "Set-Cookie",
    `session=${sessionToken}; HttpOnly; Secure; SameSite=Lax; Max-Age=${
      7 * 24 * 60 * 60
    }; Path=/`,
  );

  return new Response(null, { status: 302, headers });
}

async function handleLogout(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const redirectTo = url.searchParams.get("redirect_to") || "/";
  return new Response(null, {
    status: 302,
    headers: {
      Location: redirectTo,
      "Set-Cookie":
        "session=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/",
    },
  });
}

// ============================================================================
// Stripe Webhook Handler with Full SDK Implementation
// ============================================================================

async function streamToBuffer(
  readableStream: ReadableStream<Uint8Array>,
): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  const reader = readableStream.getReader();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const totalLength = chunks.reduce((acc, chunk) => acc + chunk.length, 0);
  const result = new Uint8Array(totalLength);
  let position = 0;
  for (const chunk of chunks) {
    result.set(chunk, position);
    position += chunk.length;
  }
  return result;
}

async function handleStripeWebhook(
  request: Request,
  env: Env,
): Promise<Response> {
  if (!request.body) {
    return new Response(JSON.stringify({ error: "No body" }), { status: 400 });
  }

  const stripe = new Stripe(env.STRIPE_SECRET, {
    apiVersion: "2025-12-15.clover",
  });

  const rawBody = await streamToBuffer(request.body);
  const rawBodyString = new TextDecoder().decode(rawBody);
  const stripeSignature = request.headers.get("stripe-signature");

  if (!stripeSignature) {
    return new Response(JSON.stringify({ error: "No signature" }), {
      status: 400,
    });
  }

  let event: Stripe.Event;
  try {
    // Verify webhook signature using Stripe SDK
    event = await stripe.webhooks.constructEventAsync(
      rawBodyString,
      stripeSignature,
      env.STRIPE_WEBHOOK_SIGNING_SECRET,
    );
  } catch (err: any) {
    console.error("Webhook signature verification failed:", err.message);
    return new Response(JSON.stringify({ error: err.message }), {
      status: 400,
    });
  }

  // Handle checkout.session.completed event
  if (event.type === "checkout.session.completed") {
    const session = event.data.object as Stripe.Checkout.Session;

    // Verify this is the correct payment link
    if (session.payment_link !== env.STRIPE_PAYMENT_LINK_ID) {
      console.log(`Incorrect payment link ID: ${session.payment_link}`);
      return new Response(
        JSON.stringify({ received: true, message: "Incorrect payment link" }),
        { status: 200 },
      );
    }

    if (session.payment_status !== "paid" || !session.amount_total) {
      return new Response(JSON.stringify({ error: "Payment not completed" }), {
        status: 400,
      });
    }

    const { client_reference_id, customer_details, customer } = session;
    if (!client_reference_id || !customer_details?.email) {
      return new Response(
        JSON.stringify({ error: "Missing required fields" }),
        { status: 400 },
      );
    }

    const stub = env.SubscriptionDO.get(env.SubscriptionDO.idFromName(DO_NAME));
    await stub.addSubscription(
      client_reference_id,
      customer_details.email,
      customer as string,
    );

    return new Response(
      JSON.stringify({ received: true, message: "Payment processed" }),
      { status: 200 },
    );
  }

  // Handle customer.subscription.deleted event
  if (event.type === "customer.subscription.deleted") {
    const subscription = event.data.object as Stripe.Subscription;

    // Get customer details to find the username
    const customer = await stripe.customers.retrieve(subscription.customer as string);

    if (customer.deleted) {
      return new Response(
        JSON.stringify({ received: true, message: "Customer already deleted" }),
        { status: 200 },
      );
    }

    // Find subscription by customer email
    const stub = env.SubscriptionDO.get(env.SubscriptionDO.idFromName(DO_NAME));
    await stub.removeSubscriptionByEmail(customer.email || "");

    return new Response(
      JSON.stringify({ received: true, message: "Subscription removed" }),
      { status: 200 },
    );
  }

  // Return 200 for all other event types
  return new Response(
    JSON.stringify({ received: true, message: "Event not handled" }),
    { status: 200 },
  );
}

// ============================================================================
// Main Worker
// ============================================================================

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // OAuth routes
    if (path === "/login") return handleLogin(request, env);
    if (path === "/callback") return handleCallback(request, env);
    if (path === "/logout") return handleLogout(request);

    // Stripe webhook
    if (path === "/webhook/stripe") {
      return handleStripeWebhook(request, env);
    }

    // API: Get logged in user info
    if (path === "/api/user") {
      const user = getCurrentUser(request);
      if (!user) {
        return new Response(JSON.stringify({ error: "Not authenticated" }), {
          status: 401,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response(JSON.stringify(user), {
        headers: { "Content-Type": "application/json" },
      });
    }

    // API: Create Stripe customer portal session
    if (path === "/api/create-portal-session") {
      const user = getCurrentUser(request);
      if (!user) {
        return new Response(JSON.stringify({ error: "Not authenticated" }), {
          status: 401,
          headers: { "Content-Type": "application/json" },
        });
      }

      const stub = env.SubscriptionDO.get(
        env.SubscriptionDO.idFromName(DO_NAME),
      );
      const customerId = await stub.getStripeCustomerId(user.login);

      if (!customerId) {
        return new Response(JSON.stringify({ error: "No subscription found" }), {
          status: 404,
          headers: { "Content-Type": "application/json" },
        });
      }

      const stripe = new Stripe(env.STRIPE_SECRET, {
        apiVersion: "2025-12-15.clover",
      });

      const session = await stripe.billingPortal.sessions.create({
        customer: customerId,
        return_url: `${url.origin}/dashboard`,
      });

      return new Response(JSON.stringify({ url: session.url }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    // Public context endpoint (exclude root path, api paths, and static assets)
    const contextMatch = path.match(/^\/([^\/]+)$/);
    // Dashboard (requires auth)
    if (path === "/dashboard") {
      const user = getCurrentUser(request);
      if (!user) {
        return new Response(null, {
          status: 302,
          headers: {
            Location: "/login?redirect_to=/dashboard",
          },
        });
      }

      const stub = env.SubscriptionDO.get(
        env.SubscriptionDO.idFromName(DO_NAME),
      );
      const isSubscribed = await stub.isSubscribed(user.login);

      // Update access token if user is subscribed
      if (isSubscribed) {
        const accessToken = getAccessToken(request);
        if (accessToken) {
          await stub.updateAccessToken(user.login, accessToken);
        }
      }

      const context = isSubscribed ? await stub.getContext(user.login) : null;

      const paymentLink = `${
        env.STRIPE_PAYMENT_LINK
      }?client_reference_id=${encodeURIComponent(user.login)}`;

      const html = `<!DOCTYPE html>
<html lang="en" class="bg-black">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Context Subscription</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    @import url("https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap");
    body { font-family: "Inter", sans-serif; }
  </style>
</head>
<body class="text-gray-100">
  <main class="max-w-4xl mx-auto px-4 py-8">
    <div class="flex justify-between items-center mb-8">
      <h1 class="text-3xl font-bold bg-gradient-to-r from-purple-400 to-pink-600 bg-clip-text text-transparent">
        Context Subscription
      </h1>
      <div class="flex items-center gap-4">
        <img src="${user.avatar_url}" class="w-10 h-10 rounded-full" alt="${
        user.login
      }">
        <span>${user.login}</span>
        <a href="/logout" class="text-purple-400 hover:text-purple-300">Logout</a>
      </div>
    </div>

    <div class="bg-purple-900/30 border border-purple-800 p-6 rounded-lg mb-6">
      <h2 class="text-xl font-semibold mb-4">Subscription Status</h2>
      ${
        isSubscribed
          ? `
        <div class="flex items-center gap-2 text-green-400 mb-4">
          <svg class="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
          </svg>
          <span class="font-medium">Active Subscription</span>
        </div>
        <p class="text-gray-400 mb-4">$10/month - Updates daily at 2 AM UTC</p>
        <button onclick="manageSubscription()" class="bg-purple-700 hover:bg-purple-600 px-6 py-3 rounded-lg font-medium transition-colors">
          Manage Subscription
        </button>
      `
          : `
        <div class="flex items-center gap-2 text-yellow-400 mb-4">
          <svg class="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
            <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/>
          </svg>
          <span class="font-medium">Not Subscribed</span>
        </div>
        <p class="text-gray-400 mb-4">Subscribe for $10/month to get daily context updates</p>
        <a href="${paymentLink}" class="inline-block bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600 px-6 py-3 rounded-lg font-medium transition-colors">
          Subscribe Now
        </a>
      `
      }
    </div>

    ${
      context
        ? `
      <div class="bg-purple-900/30 border border-purple-800 p-6 rounded-lg">
        <div class="flex justify-between items-center mb-4">
          <h2 class="text-xl font-semibold">Your Context</h2>
          <button onclick="copyContext()" class="bg-purple-700 hover:bg-purple-600 px-4 py-2 rounded-lg transition-colors">
            Copy to Clipboard
          </button>
        </div>
        <div class="text-sm text-gray-400 mb-4">
          Public URL: <a href="/${
            user.login
          }" class="text-purple-400 hover:underline">context.forgithub.com/${
            user.login
          }</a>
        </div>
        <pre id="context" class="bg-black/50 p-4 rounded overflow-x-auto text-sm">${context
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")}</pre>
      </div>
    `
        : isSubscribed
          ? `
      <div class="bg-purple-900/30 border border-purple-800 p-6 rounded-lg">
        <div class="flex items-center gap-3 mb-4">
          <svg class="w-8 h-8 text-purple-400 animate-spin" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg>
          <div>
            <h2 class="text-xl font-semibold">Context Loading...</h2>
            <p class="text-gray-400">Your context is being generated. This may take a few moments.</p>
          </div>
        </div>
        <p class="text-sm text-gray-500">Refresh this page in a minute to see your context.</p>
      </div>
    `
          : ""
    }

    <script>
      function copyContext() {
        const text = document.getElementById('context').textContent;
        navigator.clipboard.writeText(text).then(() => {
          alert('Context copied to clipboard!');
        });
      }

      async function manageSubscription() {
        try {
          const response = await fetch('/api/create-portal-session');
          const data = await response.json();
          if (data.url) {
            window.location.href = data.url;
          } else {
            alert('Failed to create portal session');
          }
        } catch (error) {
          alert('Error: ' + error.message);
        }
      }
    </script>
  </main>
</body>
</html>`;

      return new Response(html, { headers: { "Content-Type": "text/html" } });
    }

    if (contextMatch && !path.startsWith("/api/") && path !== "/") {
      const username = contextMatch[1];
      const stub = env.SubscriptionDO.get(
        env.SubscriptionDO.idFromName(DO_NAME),
      );
      const context = await stub.getContext(username);

      if (!context) {
        return new Response("User not subscribed or context not available", {
          status: 404,
        });
      }

      return new Response(context, {
        headers: { "Content-Type": "text/markdown" },
      });
    }

    return new Response("Not Found", { status: 404 });
  },

  async scheduled(event, env: Env, ctx: ExecutionContext): Promise<void> {
    const stub = env.SubscriptionDO.get(env.SubscriptionDO.idFromName(DO_NAME));
    await stub.updateAllContexts();
  },
} satisfies ExportedHandler<Env>;

// ============================================================================
// Durable Object
// ============================================================================

export class SubscriptionDO extends DurableObject<Env> {
  sql: SqlStorage;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.sql = state.storage.sql;
    this.initDatabase();
  }

  private initDatabase() {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS subscriptions (
        username TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        subscribed_at INTEGER NOT NULL,
        access_token TEXT,
        context TEXT,
        context_updated_at INTEGER,
        stripe_customer_id TEXT
      )
    `);
  }

  async addSubscription(username: string, email: string, stripeCustomerId?: string): Promise<void> {
    const now = Date.now();
    this.sql.exec(
      `INSERT OR REPLACE INTO subscriptions (username, email, subscribed_at, context_updated_at, stripe_customer_id)
       VALUES (?, ?, ?, ?, ?)`,
      username,
      email,
      now,
      0,
      stripeCustomerId || null,
    );
    // Trigger initial context calculation
    await this.updateContext(username);
  }

  async removeSubscriptionByEmail(email: string): Promise<void> {
    this.sql.exec(
      "DELETE FROM subscriptions WHERE email = ?",
      email,
    );
  }

  async isSubscribed(username: string): Promise<boolean> {
    const result = this.sql.exec(
      "SELECT username FROM subscriptions WHERE username = ?",
      username,
    );
    return result.toArray().length > 0;
  }

  async getStripeCustomerId(username: string): Promise<string | null> {
    const result = this.sql.exec(
      "SELECT stripe_customer_id FROM subscriptions WHERE username = ?",
      username,
    );
    const rows = result.toArray();
    return rows.length > 0 ? (rows[0] as any).stripe_customer_id : null;
  }

  async getContext(username: string): Promise<string | null> {
    const result = this.sql.exec(
      "SELECT context FROM subscriptions WHERE username = ?",
      username,
    );
    const rows = result.toArray();
    return rows.length > 0 ? (rows[0] as any).context : null;
  }

  async updateAccessToken(
    username: string,
    accessToken: string,
  ): Promise<void> {
    this.sql.exec(
      "UPDATE subscriptions SET access_token = ? WHERE username = ?",
      accessToken,
      username,
    );
  }

  async updateAllContexts(): Promise<void> {
    const result = this.sql.exec("SELECT username FROM subscriptions");
    const users = result.toArray() as Array<{ username: string }>;

    for (const user of users) {
      await this.updateContext(user.username);
    }
  }

  private async updateContext(username: string): Promise<void> {
    try {
      // Get access token for the user
      const result = this.sql.exec(
        "SELECT access_token FROM subscriptions WHERE username = ?",
        username,
      );
      const rows = result.toArray();
      if (rows.length === 0) {
        console.error(`No subscription found for ${username}`);
        return;
      }

      const accessToken = (rows[0] as any).access_token;
      if (!accessToken) {
        console.error(`No access token stored for ${username}`);
        return;
      }

      // Fetch all repositories from GitHub API
      const repos: any[] = [];
      let page = 1;
      const perPage = 100;

      while (true) {
        const response = await fetch(
          `https://api.github.com/user/repos?per_page=${perPage}&page=${page}&affiliation=owner,organization_member`,
          {
            headers: {
              Authorization: `Bearer ${accessToken}`,
              Accept: "application/vnd.github.v3+json",
              "User-Agent": "Context-Subscription/1.0",
            },
          },
        );

        if (!response.ok) {
          console.error(
            `Failed to fetch repos for ${username}: ${response.status}`,
          );
          return;
        }

        const pageRepos = await response.json();
        if (!Array.isArray(pageRepos) || pageRepos.length === 0) break;

        repos.push(...pageRepos);

        // If we got fewer than perPage repos, we're done
        if (pageRepos.length < perPage) break;
        page++;
      }

      const context = this.formatContext(username, repos);

      this.sql.exec(
        "UPDATE subscriptions SET context = ?, context_updated_at = ? WHERE username = ?",
        context,
        Date.now(),
        username,
      );
    } catch (error) {
      console.error(`Error updating context for ${username}:`, error);
    }
  }

  private formatContext(username: string, repos: any[]): string {
    let context = `# Context for ${username}\n\n`;
    context += `Updated: ${new Date().toISOString()}\n`;
    context += `Total Repositories: ${repos.length}\n\n`;

    // Group repositories by category
    const ownRepos: any[] = [];
    const forkedRepos: any[] = [];
    const orgRepos: { [org: string]: any[] } = {};

    for (const repo of repos) {
      if (repo.owner.type === "Organization") {
        const orgName = repo.owner.login;
        if (!orgRepos[orgName]) {
          orgRepos[orgName] = [];
        }
        orgRepos[orgName].push(repo);
      } else if (repo.fork) {
        forkedRepos.push(repo);
      } else {
        ownRepos.push(repo);
      }
    }

    // Format own repositories
    if (ownRepos.length > 0) {
      context += `## Own Repositories (${ownRepos.length})\n\n`;
      for (const repo of ownRepos) {
        context += this.formatRepoInfo(repo);
      }
      context += "\n";
    }

    // Format organization repositories
    const orgNames = Object.keys(orgRepos).sort();
    if (orgNames.length > 0) {
      context += `## Organization Repositories\n\n`;
      for (const orgName of orgNames) {
        const repos = orgRepos[orgName];
        context += `### ${orgName} (${repos.length})\n\n`;
        for (const repo of repos) {
          context += this.formatRepoInfo(repo);
        }
        context += "\n";
      }
    }

    // Format forked repositories
    if (forkedRepos.length > 0) {
      context += `## Forked Repositories (${forkedRepos.length})\n\n`;
      for (const repo of forkedRepos) {
        context += this.formatRepoInfo(repo);
      }
      context += "\n";
    }

    return context;
  }

  private formatRepoInfo(repo: any): string {
    let info = `- **${repo.full_name}**`;

    if (repo.description) {
      info += `: ${repo.description}`;
    }

    info += "\n";

    if (repo.homepage) {
      info += `  - Homepage: ${repo.homepage}\n`;
    }

    if (repo.topics && repo.topics.length > 0) {
      info += `  - Tags: ${repo.topics.join(", ")}\n`;
    }

    return info;
  }
}
