/**
 * Base44 Secure Proxy – Production-Ready Express Server
 * -----------------------------------------------------
 * What it does
 *  - Provides secure endpoints your frontend can call without exposing the Base44 API key
 *  - Supports filtering, pagination, and sorting for ServiceRequest reads
 *  - Supports updates with strict validation and field allow-listing
 *  - Adds security hardening, rate-limiting, input validation, robust error handling & timeouts
 *
 * How to run
 *  1) Save this file as server.js
 *  2) `npm init -y`
 *  3) `npm i express helmet cors express-rate-limit zod dotenv node-fetch@3 pino pino-http`
 *  4) Create a .env file (never commit it):
 *        PORT=8080
 *        BASE44_API_BASE=https://app.base44.com/api
 *        BASE44_APP_ID=689fc0a014e4ed3d523dc4e3
 *        BASE44_API_KEY=your_real_api_key_here
 *        REQUEST_TIMEOUT_MS=10000
 *  5) `node server.js`
 *
 * Minimal frontend example (call your proxy, not Base44 directly):
 *    fetch('/api/servicerequests?status=pending&is_emergency=true')
 *      .then(r => r.json()).then(console.log)
 *
 * Notes
 *  - Adjust CORS origins below.
 *  - Add authentication (JWT/session) where indicated if this runs on the public internet.
 */

import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import fetch, { AbortError } from 'node-fetch';
import { z } from 'zod';
import pino from 'pino';
import pinoHttp from 'pino-http';

const logger = pino({ level: process.env.NODE_ENV === 'production' ? 'info' : 'debug' });

// ---------- Config ----------
const PORT = Number(process.env.PORT || 8080);
const BASE44_API_BASE = process.env.BASE44_API_BASE || 'https://app.base44.com/api';
const BASE44_APP_ID = process.env.BASE44_APP_ID; // required
const BASE44_API_KEY = process.env.BASE44_API_KEY; // required
const REQUEST_TIMEOUT_MS = Number(process.env.REQUEST_TIMEOUT_MS || 10000);

if (!BASE44_APP_ID || !BASE44_API_KEY) {
  logger.error('Missing BASE44_APP_ID or BASE44_API_KEY in environment');
  process.exit(1);
}

const BASE44_ENTITY_URL = `${BASE44_API_BASE}/apps/${BASE44_APP_ID}/entities/ServiceRequest`;

// ---------- Express Setup ----------
const app = express();
app.set('trust proxy', 1);

app.use(pinoHttp({ logger }));
app.use(helmet({
  contentSecurityPolicy: process.env.NODE_ENV === 'production' ? undefined : false,
}));

// Tighten CORS to your known domains in production
app.use(cors({
  origin: [/localhost:\d+$/, /127\.0\.0\.1:\d+$/],
  methods: ['GET', 'PUT', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));

app.use(express.json({ limit: '100kb' }));

// Basic rate limiting – tune to your needs
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', limiter);

// ---- Optional: plug in your auth middleware here ----
// app.use('/api', requireAuth());

// ---------- Validation Schemas ----------
const filterableFields = [
  'name', 'email', 'phone', 'service_type', 'description', 'address',
  'preferred_date', 'is_emergency', 'status'
] as const;

const listQuerySchema = z.object({
  // Filters (all optional)
  name: z.string().trim().min(1).optional(),
  email: z.string().email().optional(),
  phone: z.string().trim().min(5).max(30).optional(),
  service_type: z.string().trim().optional(),
  description: z.string().trim().optional(),
  address: z.string().trim().optional(),
  preferred_date: z.string().trim().optional(), // consider normalizing to ISO date
  is_emergency: z.union([z.literal('true'), z.literal('false')]).optional(),
  status: z.string().trim().optional(),

  // Pagination & sorting
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(200).default(25),
  sortBy: z.enum([...filterableFields]).optional(),
  sortDir: z.enum(['asc', 'desc']).default('asc'),
});

const updateSchema = z.object({
  name: z.string().trim().min(1).max(200).optional(),
  email: z.string().email().optional(),
  phone: z.string().trim().min(5).max(30).optional(),
  service_type: z.string().trim().max(100).optional(),
  description: z.string().trim().max(2000).optional(),
  address: z.string().trim().max(300).optional(),
  preferred_date: z.string().trim().max(100).optional(), // or z.string().datetime().optional()
  is_emergency: z.boolean().optional(),
  status: z.string().trim().max(100).optional(),
}).refine(obj => Object.keys(obj).length > 0, {
  message: 'At least one updatable field is required',
});

// ---------- Helpers ----------
function toQueryString(params) {
  const url = new URL(BASE44_ENTITY_URL);
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue;
    url.searchParams.append(k, String(v));
  }
  return url.toString();
}

async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    const text = await res.text();
    let data;
    try { data = text ? JSON.parse(text) : null; } catch { data = text; }

    if (!res.ok) {
      const err = new Error(data?.message || `Upstream error ${res.status}`);
      err.status = res.status;
      err.details = data;
      throw err;
    }
    return { status: res.status, data, headers: res.headers };
  } catch (err) {
    if (err instanceof AbortError) {
      err.status = 504;
      err.message = 'Upstream timeout';
    }
    throw err;
  } finally {
    clearTimeout(timeout);
  }
}

function base44Headers() {
  return {
    'api_key': BASE44_API_KEY,
    'Content-Type': 'application/json',
  };
}

// Whitelist only the filterable fields to forward upstream
function pickFilters(query) {
  const picked = {};
  for (const f of filterableFields) {
    if (query[f] !== undefined) picked[f] = query[f];
  }
  return picked;
}

// ---------- Routes ----------
// GET /api/servicerequests – list with filters + pagination + sorting
app.get('/api/servicerequests', async (req, res, next) => {
  try {
    const q = listQuerySchema.parse(req.query);

    // Map page/pageSize to upstream if supported; otherwise do client-side slicing after fetch.
    // Assuming upstream supports query params directly for filters; pass only allow-listed fields.
    const filters = pickFilters(q);

    // Sorting & pagination strategy: if Base44 supports sort/pagination, add here.
    // If not, you may need to fetch all (if small) and paginate locally.
    const upstreamUrl = toQueryString({ ...filters });

    const { data, headers } = await fetchWithTimeout(upstreamUrl, { headers: base44Headers() });

    // If upstream does not paginate, implement local pagination
    const items = Array.isArray(data) ? data : (data?.items || []);
    const total = Array.isArray(data) ? data.length : (data?.total || items.length);

    // local sort if requested
    let sorted = items;
    if (q.sortBy) {
      const dir = q.sortDir === 'desc' ? -1 : 1;
      sorted = [...items].sort((a, b) => {
        const av = a?.[q.sortBy];
        const bv = b?.[q.sortBy];
        if (av == null && bv == null) return 0;
        if (av == null) return -1 * dir;
        if (bv == null) return 1 * dir;
        return String(av).localeCompare(String(bv)) * dir;
      });
    }

    const start = (q.page - 1) * q.pageSize;
    const end = start + q.pageSize;
    const pageItems = sorted.slice(start, end);

    res.setHeader('Cache-Control', 'private, max-age=30');
    return res.json({
      page: q.page,
      pageSize: q.pageSize,
      total,
      items: pageItems,
    });
  } catch (err) {
    next(err);
  }
});

// PUT /api/servicerequests/:id – update allow-listed fields
app.put('/api/servicerequests/:id', async (req, res, next) => {
  try {
    const id = z.string().min(1).parse(req.params.id);
    const body = updateSchema.parse(req.body);

    // Forward the validated body to Base44
    const url = `${BASE44_ENTITY_URL}/${encodeURIComponent(id)}`;

    const { data } = await fetchWithTimeout(url, {
      method: 'PUT',
      headers: base44Headers(),
      body: JSON.stringify(body),
    });

    res.setHeader('Cache-Control', 'no-store');
    return res.json(data);
  } catch (err) {
    next(err);
  }
});

// Health check
app.get('/healthz', (_req, res) => res.json({ ok: true }));

// ---------- Error Handler ----------
// Centralized error mapping, no stack traces in prod responses
app.use((err, req, res, _next) => {
  req.log?.error({ err }, 'Request failed');
  const status = Number(err.status) || 500;
  const payload = {
    error: status >= 500 ? 'Internal Server Error' : 'Request Failed',
    message: process.env.NODE_ENV === 'production' && status >= 500 ? undefined : err.message,
    details: process.env.NODE_ENV === 'production' ? undefined : err.details,
  };
  res.status(status).json(payload);
});

app.listen(PORT, () => {
  logger.info({ PORT }, 'Secure Base44 proxy listening');
});
