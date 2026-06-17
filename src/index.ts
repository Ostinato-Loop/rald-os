// RALD OS — Ecosystem API Gateway
// api.rald.cloud — Phase 7: Single entry point for every RALD service.
// Products talk through the OS instead of directly to each other.
//
// GET  /identity/:username_or_rald_id   → rald_users + trust profile
// GET  /wallet/:rald_id                 → payrald wallet
// GET  /mail/:rald_id                   → rald mail account
// GET  /trust/:rald_id                  → trust profile
// GET  /alias/:handle                   → ALIA resolution
// GET  /products                        → product registry
// GET  /products/:slug/health           → product health
// GET  /ecosystem/health                → all products health aggregation
// GET  /events/stream                   → SSE stream of recent events
// POST /events                          → ingest event (machine auth)
// GET  /health, /readyz, /version
// LILCKY STUDIO LIMITED · 2026-06-17

import { Hono } from "hono";
import { cors } from "hono/cors";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";

const VERSION = "1.0.0";
const SERVICE = "rald-os";

export type Bindings = {
  SUPABASE_URL:              string;
  SUPABASE_SERVICE_ROLE_KEY: string;
  RALD_JWT_SECRET:           string;
  RALD_INTERNAL_SECRET?:     string;
  ENVIRONMENT:               string;
  // Upstream service URLs
  AUTH_URL?:      string;   // https://auth.rald.cloud
  EVENTS_URL?:    string;   // https://events.rald.cloud
  PAY_URL?:       string;   // https://pay.rald.cloud
};

export type Variables = {
  db: SupabaseClient;
};

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── Health (pre-middleware) ───────────────────────────────────────────────────
app.get("/health",  (c) => c.json({ status: "ok", service: SERVICE, version: VERSION, timestamp: new Date().toISOString() }));
app.get("/healthz", (c) => c.json({ status: "ok", service: SERVICE, timestamp: new Date().toISOString() }));
app.get("/readyz",  (c) => c.json({ status: "ok" }));
app.get("/version", (c) => c.json({ service: SERVICE, version: VERSION, owner: "LILCKY STUDIO LIMITED", environment: c.env.ENVIRONMENT ?? "production" }));

// ── Security headers ──────────────────────────────────────────────────────────
app.use("*", async (c, next) => {
  await next();
  c.header("X-Content-Type-Options",   "nosniff");
  c.header("X-Frame-Options",          "DENY");
  c.header("Strict-Transport-Security","max-age=31536000; includeSubDomains");
  c.header("Referrer-Policy",          "strict-origin-when-cross-origin");
  c.header("X-RALD-OS-Version",        VERSION);
  c.header("X-RALD-Service",           SERVICE);
});

// ── CORS ──────────────────────────────────────────────────────────────────────
app.use("*", cors({
  origin: (origin) => {
    const allowed = new Set([
      "https://rald.cloud", "https://app.rald.cloud", "https://auth.rald.cloud",
      "https://pay.rald.cloud", "https://messenger.rald.cloud", "https://mail.rald.cloud",
      "https://alia.rald.cloud", "https://loop.rald.cloud", "https://admin.rald.cloud",
      "https://control.rald.cloud", "https://elimu.rald.cloud", "https://identity.rald.cloud",
      "http://localhost:3000", "http://localhost:5173",
    ]);
    if (allowed.has(origin ?? "")) return origin;
    if (/^https:\/\/[a-z0-9-]+\.rald\.cloud$/.test(origin ?? "")) return origin;
    return null;
  },
  allowMethods: ["GET", "POST", "OPTIONS"],
  allowHeaders: ["Authorization", "Content-Type", "X-RALD-Internal-Key"],
  credentials: true,
}));

// ── Supabase client per request ───────────────────────────────────────────────
app.use("*", async (c, next) => {
  if (!c.env.SUPABASE_URL || !c.env.SUPABASE_SERVICE_ROLE_KEY) {
    return c.json({ error: "Service not configured", service: SERVICE }, 503);
  }
  c.set("db", createClient(c.env.SUPABASE_URL, c.env.SUPABASE_SERVICE_ROLE_KEY));
  return next();
});

// ── Machine auth middleware (for write endpoints) ──────────────────────────────
async function requireInternal(c: any, next: any) {
  const key = c.req.header("X-RALD-Internal-Key") ?? c.req.header("Authorization")?.replace("Bearer ", "");
  if (!key || key !== c.env.RALD_INTERNAL_SECRET) {
    return c.json({ error: "Forbidden — machine auth required" }, 403);
  }
  return next();
}

// ── GET / — root ──────────────────────────────────────────────────────────────
app.get("/", (c) => c.json({
  service:     SERVICE,
  version:     VERSION,
  description: "RALD OS Ecosystem API — one gateway, every service",
  endpoints: {
    identity: "GET /identity/:rald_id_or_username",
    wallet:   "GET /wallet/:rald_id",
    mail:     "GET /mail/:rald_id",
    trust:    "GET /trust/:rald_id",
    alias:    "GET /alias/:handle",
    products: "GET /products",
    health:   "GET /ecosystem/health",
    events:   "GET /events/recent",
  },
  owner: "LILCKY STUDIO LIMITED",
  timestamp: new Date().toISOString(),
}));

// ── GET /identity/:lookup — universal identity resolution ──────────────────────
// Accepts rald_id (rld_...) or username or @username
app.get("/identity/:lookup", async (c) => {
  const db     = c.get("db");
  const raw    = c.req.param("lookup").replace(/^@/, "");
  const isRald = raw.startsWith("rld_");

  let query = db.from("rald_users")
    .select("id,username,rald_email,alia_handle,wallet_id,messenger_id,mail_id,trust_score,kyc_tier,activated_products,provision_status,created_at");

  if (isRald) query = query.eq("id", raw);
  else        query = query.eq("username", raw);

  const { data: user } = await query.maybeSingle();
  if (!user) return c.json({ error: "Identity not found" }, 404);

  // Enrich with trust tier if available
  const { data: trust } = await db
    .from("rald_trust_profiles")
    .select("trust_tier,trust_score,kyc_tier,is_merchant,is_creator,is_school,fraud_flagged")
    .eq("rald_id", user.id)
    .maybeSingle();

  return c.json({
    rald_id:            user.id,
    username:           user.username,
    rald_email:         user.rald_email,
    alia_handle:        user.alia_handle,
    wallet_id:          user.wallet_id,
    messenger_id:       user.messenger_id,
    mail_id:            user.mail_id,
    activated_products: user.activated_products,
    provision_status:   user.provision_status,
    trust: trust ? {
      tier:         trust.trust_tier,
      score:        trust.trust_score,
      kyc_tier:     trust.kyc_tier,
      is_merchant:  trust.is_merchant,
      is_creator:   trust.is_creator,
      is_school:    trust.is_school,
      fraud_flagged: trust.fraud_flagged,
    } : null,
    created_at: user.created_at,
  });
});

// ── GET /wallet/:rald_id ──────────────────────────────────────────────────────
app.get("/wallet/:rald_id", async (c) => {
  const db     = c.get("db");
  const raldId = c.req.param("rald_id");

  const { data } = await db
    .from("payrald_wallets")
    .select("id,rald_id,currency,status,created_at")  // omit balance — product-internal
    .eq("rald_id", raldId)
    .maybeSingle();

  if (!data) return c.json({ error: "Wallet not found" }, 404);
  return c.json(data);
});

// ── GET /mail/:rald_id ────────────────────────────────────────────────────────
app.get("/mail/:rald_id", async (c) => {
  const db     = c.get("db");
  const raldId = c.req.param("rald_id");

  const { data } = await db
    .from("mail_accounts")
    .select("id,rald_id,address,display_name,status,created_at")
    .eq("rald_id", raldId)
    .maybeSingle();

  if (!data) return c.json({ error: "Mail account not found" }, 404);
  return c.json(data);
});

// ── GET /trust/:rald_id ───────────────────────────────────────────────────────
app.get("/trust/:rald_id", async (c) => {
  const db     = c.get("db");
  const raldId = c.req.param("rald_id");

  const { data } = await db
    .from("rald_trust_profiles")
    .select("rald_id,trust_score,trust_tier,kyc_tier,fraud_score,reputation_score,merchant_score,school_score,is_merchant,is_creator,is_school,phone_verified,email_verified,bvn_verified,fraud_flagged,sanctions_flagged,last_computed_at")
    .eq("rald_id", raldId)
    .maybeSingle();

  if (!data) return c.json({ error: "Trust profile not found" }, 404);
  return c.json(data);
});

// ── GET /alias/:handle — ALIA handle resolution ───────────────────────────────
app.get("/alias/:handle", async (c) => {
  const db     = c.get("db");
  const handle = c.req.param("handle").replace(/^@/, "");

  const { data } = await db
    .from("alia_handles")
    .select("id,rald_id,handle,status,created_at")
    .or(`handle.eq.${handle},handle.eq.@${handle}`)
    .maybeSingle();

  if (!data) return c.json({ error: "Alias not found" }, 404);

  // Get associated identity
  const { data: identity } = await db
    .from("rald_users")
    .select("username,rald_email,wallet_id,activated_products")
    .eq("id", data.rald_id)
    .maybeSingle();

  return c.json({ ...data, identity });
});

// ── GET /products — product registry ─────────────────────────────────────────
app.get("/products", async (c) => {
  const db = c.get("db");
  const { data } = await db
    .from("rald_products")
    .select("slug,name,description,status,base_url,api_endpoint,icon_url,billing_model,auto_provision,permissions")
    .in("status", ["active","beta"])
    .order("created_at", { ascending: true });

  return c.json({ products: data ?? [], count: data?.length ?? 0, generated_at: new Date().toISOString() });
});

// ── GET /products/:slug/health ────────────────────────────────────────────────
app.get("/products/:slug/health", async (c) => {
  const db   = c.get("db");
  const slug = c.req.param("slug");

  const { data } = await db.from("rald_products").select("health_url,name,status").eq("slug", slug).maybeSingle();
  if (!data) return c.json({ error: "Product not found" }, 404);
  if (!data.health_url) return c.json({ slug, health: "unknown" });

  const t0 = Date.now();
  try {
    const res = await fetch(data.health_url as string, { signal: AbortSignal.timeout(5000) });
    return c.json({ slug, name: data.name, health: res.ok ? "ok" : "degraded", latency_ms: Date.now() - t0 });
  } catch {
    return c.json({ slug, name: data.name, health: "down", latency_ms: Date.now() - t0 });
  }
});

// ── GET /ecosystem/health — aggregate all product health ──────────────────────
app.get("/ecosystem/health", async (c) => {
  const db = c.get("db");
  const { data: prods } = await db
    .from("rald_products").select("slug,name,health_url,status").in("status", ["active","beta"]);

  const checks = await Promise.allSettled(
    (prods ?? []).map(async (p: any) => {
      if (!p.health_url) return { slug: p.slug, name: p.name, health: "unknown" };
      const t0 = Date.now();
      try {
        const r = await fetch(p.health_url, { signal: AbortSignal.timeout(4000) });
        return { slug: p.slug, name: p.name, health: r.ok ? "ok" : "degraded", latency_ms: Date.now() - t0 };
      } catch {
        return { slug: p.slug, name: p.name, health: "down", latency_ms: Date.now() - t0 };
      }
    })
  );

  const results   = checks.map(r => r.status === "fulfilled" ? r.value : { health: "error" });
  const allOk     = results.every(r => (r as any).health === "ok" || (r as any).health === "unknown");
  const degraded  = results.filter(r => (r as any).health === "degraded" || (r as any).health === "down");

  return c.json({
    ecosystem_health: allOk ? "ok" : degraded.length === results.length ? "down" : "degraded",
    service:          SERVICE,
    products:         results,
    summary: { total: results.length, healthy: results.filter(r => (r as any).health === "ok").length, degraded: degraded.length },
    generated_at:     new Date().toISOString(),
  }, allOk ? 200 : 207);
});

// ── GET /events/recent — recent events from event bus ────────────────────────
app.get("/events/recent", async (c) => {
  const db   = c.get("db");
  const type = c.req.query("type");
  const limit = Math.min(50, Number(c.req.query("limit") ?? "20"));

  let query = db
    .from("event_store")
    .select("event_id,event_type,source,user_id,created_at,status")
    .order("created_at", { ascending: false })
    .limit(limit);

  if (type) query = query.eq("event_type", type);

  const { data } = await query;
  return c.json({ events: data ?? [], count: data?.length ?? 0 });
});

// ── GET /raldtics/summary — quick OS metrics ──────────────────────────────────
app.get("/raldtics/summary", async (c) => {
  const db = c.get("db");
  const { data } = await db.from("raldtics_executive_dashboard").select("*").maybeSingle();
  return c.json({ ...data, generated_at: new Date().toISOString() });
});

app.notFound((c) => c.json({ error: "Not found", path: c.req.path, service: SERVICE }, 404));
app.onError((err, c) => {
  console.error(`[${SERVICE}] error:`, err.message ?? err);
  return c.json({ error: "Internal server error", service: SERVICE }, 500);
});

export default app;
