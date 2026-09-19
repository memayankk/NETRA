# NETRA Vercel Authentication Fix

The deployed dashboard previously returned `Authentication required` after login because sessions were stored in an in-memory Python dictionary. Vercel serverless requests can run on different function instances, so a session created by the login request was not guaranteed to exist for the next API request.

This version replaces the in-memory session store with a signed, stateless HTTP-only cookie using HMAC-SHA256. The cookie is valid across serverless instances.

Optional production environment variable: `NETRA_SESSION_SECRET` (set a long random value in Vercel). If omitted, the demo fallback secret in code is used.

The cookie is marked Secure automatically on HTTPS and remains usable on local HTTP development.
