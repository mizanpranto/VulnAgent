# A01 rules (generated from `vulnagent/a01/rules.json`)

Every rule's CWE list, severity, text and fix example comes from the registry. Neither the extractors nor the LLM choose them.

A rule may list CWEs that the official OWASP Top 10:2025 files under another category (for example CWE-942 under A02). The finding's headline CWE is the first one the official A01 list contains; the report prints the official mapping of every listed CWE next to the rule's A01 scope.

## A01-AUTHN-MISSING: Missing authentication on a sensitive endpoint

- **CWEs:** CWE-306, CWE-862 (headline CWE-862)  
- **Default severity:** high  ·  **Side:** server  ·  **Evidence kind:** absence
- **Detects:** An entry point that changes data, handles credentials/roles/payments/uploads, or returns user/order/admin data has no authentication guard (after applying global guards).
- **Impact:** Anyone on the network can call a function that should only be available to signed-in users.
- **Remediation:** Require authentication for the route (or deny by default globally) and allow-list only the intentionally public routes.
- **False-positive guards:** login/signup/password-reset-request/health/webhook-with-signature routes are allow-listed via config; global default-authentication settings are applied first; public catalogue reads are de-escalated

```
router.delete('/users/:id', requireAuth, requireRole('admin'), deleteUser)
```

## A01-AUTHZ-MISSING: Privileged action without a role or ownership check

- **CWEs:** CWE-862, CWE-285, CWE-863, CWE-284 (headline CWE-862)  
- **Default severity:** high  ·  **Side:** server  ·  **Evidence kind:** absence
- **Detects:** An authenticated entry point performs an admin-like action, or sibling routes enforce a role that this one does not.
- **Impact:** Any signed-in user can perform actions meant for administrators.
- **Remediation:** Add a role/permission guard (or an object-level policy) and test it with a non-privileged account.
- **False-positive guards:** inline role checks inside the handler count as a role check; routes behind an admin-only router guard are skipped

```
router.post('/admin/users', requireAuth, requireRole('admin'), createUser)
```

## A01-IDENTITY-FROM-REQUEST: Caller identity or role taken from request data

- **CWEs:** CWE-639, CWE-285, CWE-863 (headline CWE-639)  
- **Default severity:** high  ·  **Side:** server  ·  **Evidence kind:** presence
- **Detects:** A user id, owner id or role read from the body/query/headers/cookies is used for lookup, update or an authorization decision instead of the verified token/session. Includes guards that decide using request-supplied identity.
- **Impact:** An attacker can act as any user or claim any role by changing a request field.
- **Remediation:** Derive the caller's id and role only from the verified token or server-side session.
- **False-positive guards:** route parameters naming the target object are handled by the IDOR rule; verified identity expressions (req.user, session, current_user) are never flagged

```
const userId = req.user.id; // set by the verified auth middleware, never from req.body
```

## A01-IDOR: Object accessed by request-supplied id without ownership check

- **CWEs:** CWE-639, CWE-862, CWE-285 (headline CWE-639)  
- **Default severity:** high  ·  **Side:** server  ·  **Evidence kind:** heuristic
- **Detects:** A lookup, update or delete uses an id from the request with no owner/tenant filter and no ownership comparison.
- **Impact:** A signed-in user can read or change other users' records by changing an id.
- **Remediation:** Scope every query by the authenticated user (owner/tenant) or verify ownership before acting.
- **False-positive guards:** a filter key carrying the verified identity scopes the query; an ownership comparison or policy call in the handler suppresses the rule; admin-only routes are skipped

```
const doc = await Order.findOne({ _id: req.params.id, owner: req.user.id })
```

## A01-PRIV-ASSIGN: Privilege escalation through role assignment or mass assignment

- **CWEs:** CWE-285, CWE-269, CWE-266, CWE-915 (headline CWE-285)  
- **Default severity:** critical  ·  **Side:** server  ·  **Evidence kind:** presence
- **Detects:** A privileged role is granted in a registration path, a role/permission field is assigned from request data, or a whole request body is bound to a model that has privileged fields.
- **Impact:** Anyone can make themselves an administrator.
- **Remediation:** Set roles on the server only; bind requests to an explicit allow-list of fields.
- **False-positive guards:** pick/omit/permit allow-lists remove the taint; literal default roles such as 'user' are not privileged

```
const { name, email, password } = req.body; await User.create({ name, email, password, role: 'user' })
```

## A01-GUARD-FAIL-OPEN: Authorization guard fails open

- **CWEs:** CWE-285, CWE-636 (headline CWE-285)  
- **Default severity:** critical  ·  **Side:** server  ·  **Evidence kind:** presence
- **Detects:** A guard writes an error response (or swallows an exception) but a path still reaches the protected code.
- **Impact:** The check can be bypassed, so the protected routes are effectively public.
- **Remediation:** Return or throw immediately after denying; never call next()/proceed from an error path.
- **False-positive guards:** return/throw right after the deny response ends the path; next(err) in an error callback that returns is not a proceed

```
if (!token) { return res.status(401).json({ error: 'unauthorized' }); }
```

## A01-GUARD-COVERAGE: Guard does not cover every route it should

- **CWEs:** CWE-285, CWE-862, CWE-284 (headline CWE-285)  
- **Default severity:** high  ·  **Side:** server  ·  **Evidence kind:** heuristic
- **Detects:** A guard applies only to some HTTP methods, is registered after the routes it should protect, or admin paths sit outside the guarded prefix.
- **Impact:** Some routes (other methods, earlier routes, admin paths) are reachable without the check.
- **Remediation:** Register guards before routes, apply them to all methods, and guard whole prefixes.
- **False-positive guards:** routes that are intentionally public are skipped

```
app.use('/admin', requireAuth, requireRole('admin'), adminRouter)
```

## A01-PATH-TRAVERSAL: Request data reaches a file API without containment

- **CWEs:** CWE-22, CWE-23, CWE-36, CWE-552 (headline CWE-22)  
- **Default severity:** high  ·  **Side:** server  ·  **Evidence kind:** presence
- **Detects:** Request data reaches a file read/write/delete/send/extract API with no normalisation and base-directory check (includes zip-slip).
- **Impact:** An attacker can read, overwrite or delete arbitrary files on the server.
- **Remediation:** Resolve the path, verify it stays inside the base directory, or map ids to files.
- **False-positive guards:** basename()/secure_filename() sanitise; a startsWith/is_relative_to containment check in the handler suppresses the rule

```
const p = path.resolve(BASE, name); if (!p.startsWith(BASE + path.sep)) return res.sendStatus(400)
```

## A01-SSRF: Server-side request forgery

- **CWEs:** CWE-918 (headline CWE-918)  
- **Default severity:** high  ·  **Side:** server  ·  **Evidence kind:** presence
- **Detects:** Request data chooses the URL or host of a server-side HTTP client, URL fetcher or renderer with no allow-list.
- **Impact:** An attacker can make the server call internal services or cloud metadata endpoints.
- **Remediation:** Allow-list schemes and hosts, resolve and block private/link-local ranges, disable blind redirects.
- **False-positive guards:** a fixed scheme+host prefix means only the path is user-controlled; an allow-list/validation condition on the value suppresses the rule

```
if (!ALLOWED_HOSTS.has(new URL(url).hostname)) return res.sendStatus(400)
```

## A01-OPEN-REDIRECT: Open redirect

- **CWEs:** CWE-601 (headline CWE-601)  
- **Default severity:** medium  ·  **Side:** server  ·  **Evidence kind:** presence
- **Detects:** Request data is used as a redirect location without an allow-list.
- **Impact:** Attackers can send victims to phishing sites through a trusted domain.
- **Remediation:** Redirect only to relative paths or allow-listed hosts.
- **False-positive guards:** a fixed relative prefix is safe; an allow-list check on the value suppresses the rule

```
const dest = ALLOWED.includes(next) ? next : '/'; res.redirect(dest)
```

## A01-CSRF: State-changing cookie/session-authenticated route without CSRF protection

- **CWEs:** CWE-352 (headline CWE-352)  
- **Default severity:** medium  ·  **Side:** server  ·  **Evidence kind:** absence
- **Detects:** A state-changing route authenticated by cookie or session has no CSRF token, SameSite or Origin check, or CSRF protection is explicitly disabled.
- **Impact:** A malicious site can make a signed-in victim's browser perform actions.
- **Remediation:** Enable CSRF tokens (or SameSite=Lax/Strict plus Origin checks) for session-authenticated routes.
- **False-positive guards:** Django/Spring/Rails/Laravel enable CSRF by default: only explicit disabling is flagged; bearer-token-only APIs are not cookie authenticated

```
app.use(csrf({ cookie: { sameSite: 'strict' } }))
```

## A01-CORS: CORS misconfiguration

- **CWEs:** CWE-942 (headline CWE-942)  
- **Default severity:** medium  ·  **Side:** server  ·  **Evidence kind:** presence
- **Detects:** Reflected Origin, wildcard origin with credentials, over-broad origin patterns, or default permissive CORS on an authenticated API.
- **Impact:** Any website can read authenticated responses from the API in a victim's browser.
- **Remediation:** Allow-list exact origins; never combine wildcard/reflected origins with credentials.
- **False-positive guards:** wildcard without credentials on an unauthenticated API is low severity

```
app.use(cors({ origin: ['https://app.example.com'], credentials: true }))
```

## A01-DATA-EXPOSURE: Sensitive fields or whole collections returned without restriction

- **CWEs:** CWE-200, CWE-201, CWE-359, CWE-538, CWE-540 (headline CWE-200)  
- **Default severity:** high  ·  **Side:** server  ·  **Evidence kind:** heuristic
- **Detects:** A response is built from a whole model object or collection that has sensitive fields (password hash, token, secret) without projection, or a serializer exposes all fields.
- **Impact:** Credential hashes, tokens or other users' data are disclosed to callers.
- **Remediation:** Project explicit safe fields (DTO/serializer allow-list) and restrict collection endpoints by role.
- **False-positive guards:** select/exclude/values/only projections suppress the rule; models without sensitive fields are not flagged

```
const users = await User.find().select('name email')
```

## A01-INSECURE-DEFAULTS: Dangerous permission or exposure default

- **CWEs:** CWE-276, CWE-732, CWE-538, CWE-548, CWE-377 (headline CWE-276)  
- **Default severity:** medium  ·  **Side:** config  ·  **Evidence kind:** presence
- **Detects:** World-writable permissions, the project root or sensitive files served statically, directory listing, or backup/config/.env files inside web-served directories.
- **Impact:** Local users or remote visitors can modify or download files that should be private.
- **Remediation:** Use restrictive modes (0o600/0o750), serve a dedicated public directory, and keep secrets and backups out of it.
- **False-positive guards:** conventional public directories are only flagged when they contain sensitive file names

```
app.use(express.static(path.join(__dirname, 'public')))
```

## A01-CLIENT-ONLY: Role check exists only in client-side code

- **CWEs:** CWE-602, CWE-285 (headline CWE-285)  
- **Default severity:** low  ·  **Side:** client  ·  **Evidence kind:** heuristic
- **Detects:** Front-end code hides or shows features by role, and the server endpoints it calls have no matching server-side role check. Supporting evidence for the server-side finding.
- **Impact:** Hiding a button does not stop a user calling the endpoint directly.
- **Remediation:** Enforce the same role check on the server; treat client checks as UX only.
- **False-positive guards:** only reported when a matching server endpoint lacks a role guard; never reported above low severity

```
router.get('/admin/stats', requireAuth, requireRole('admin'), stats)
```

## A01-TOKEN-SESSION: Token or session identity weakness

- **CWEs:** CWE-613, CWE-285, CWE-922 (headline CWE-285)  
- **Default severity:** medium  ·  **Side:** server  ·  **Evidence kind:** presence
- **Detects:** Tokens issued without an expiry, tokens decoded without verification and used as identity, or a single static API key used as the only access control.
- **Impact:** Stolen or forged tokens stay valid forever or are accepted without proof.
- **Remediation:** Verify signatures, set short expiries, and use scoped, rotatable credentials.
- **False-positive guards:** expiresIn/exp present means no finding

```
jwt.sign({ sub: user.id }, SECRET, { expiresIn: '15m' })
```

## Known gaps

- Only **Python** and **JavaScript/TypeScript** extractors are complete. **Java (Spring)** and **C# (ASP.NET Core)** extractors cover routes, annotations/attributes and global security configuration only; **PHP, Go and Ruby** are skeletons that are reported as "not analysed".
- GraphQL resolvers, RPC, queue consumers and scheduled jobs are not enumerated as entry points.
- Absence-based findings (missing authentication/authorization, CSRF) are never "confirmed".
- Authorization done inside a helper/service the extractor cannot resolve can cause IDOR false positives; admin-only checks done by a reverse proxy or gateway are invisible.
- Per-rule vulnerable/safe fixtures, the multi-app A01 benchmark script with thresholds, and measurements on third-party apps (Juice Shop, NodeGoat, DVNA, WebGoat, DVWA, VAmPI, django.nV) are **not done yet**.
