# Language Patterns — TypeScript / Node.js

Express, NestJS, Next.js, Fastify, and the surrounding Node ecosystem. For Python see `lang-python.md`. For Odoo see `lang-odoo.md`.

## Express / Fastify

- **Body parsers** — verify size limits (`express.json({ limit: "100kb" })`). Default 100kb but custom configs often raise to MB.
- **Helmet** missing — banner missing CSP, HSTS, X-Frame-Options. Defense in depth, not always blocking.
- **CORS** — `cors({ origin: true, credentials: true })` reflects any Origin with credentials. ATO via CSRF.
- **express.static** with user path → traversal. `express.static(path.join(__dirname, "public", req.params.dir))` is the bug.
- **Trust proxy** misconfigured — `app.set("trust proxy", true)` lets attacker spoof `X-Forwarded-For`.
- Path-to-regexp ReDoS — known issue with certain pattern shapes.

## NestJS

- `@Param()`/`@Query()` decoded but not validated. Use `class-validator` + `ValidationPipe({ whitelist: true, forbidNonWhitelisted: true })`.
- Guards: `@UseGuards()` on controller doesn't inherit to nested controllers. Verify per-route.
- `@Body()` with `transform: true` and no `whitelist` → mass assignment.
- Microservice transports (Redis/NATS/Kafka) — verify auth at transport layer, not app layer.

## Next.js

- **API routes** in `pages/api` and route handlers in `app/`: server-side, run in Node. Treat like Express.
- **`getServerSideProps` / Server Actions:** validate inputs. Server Actions invoked via `<form action={action}>` — don't assume the binding is private.
- **`dangerouslySetInnerHTML`** — XSS. Hunt for `__html: someValue` where `someValue` is user data.
- **`next/image` loader** — custom loaders that fetch arbitrary URLs = SSRF.
- **`unstable_cache`** keyed on user input — cache poisoning if attacker controls key.
- **NextAuth / Auth.js** session strategy: JWT vs database. JWT default, signing key in env. Verify rotation, exp.
- **Middleware** runs at edge — don't put heavy auth logic there, runs Node-incompatible runtime.
- **CVE-2025-29927** middleware bypass via `x-middleware-subrequest` — patched but verify version.

## Database / ORM

- **Prisma** — `$queryRawUnsafe` with concat = SQL injection. `$queryRaw` with template literal is safe. `db.user.findMany({ where: { email: req.query.email } })` safe.
- **TypeORM** — `query()` with concat unsafe. `find({ where: ... })` safe. `getRepository(User).query(\`SELECT \* FROM users WHERE id = ${id}\`)` is the bug.
- **Sequelize** — `Op.like` with user input — verify it's escaped (it is, but `literal()` isn't).
- **Knex** — `knex.raw("...?", [val])` safe. `knex.raw(\`...\${val}\`)` unsafe.
- **MongoDB** — `find({ $where: \`this.x == ${userInput}\` })` is JavaScript injection on the server. Operator injection via JSON object payload (`{"$ne": null}`) bypasses equality.

## Crypto / Auth

- `crypto.randomBytes` good. `Math.random()` for tokens = bad.
- `bcrypt` cost < 10 = weak. `argon2id` preferred.
- `jsonwebtoken` with `verify(token, secret)` and `algorithms` not specified — accepts `none` algorithm in older versions. Use `verify(token, secret, { algorithms: ["HS256"] })`.
- `crypto.createHmac` with user-supplied algorithm → algorithm confusion.
- Cookie flags: `httpOnly`, `secure`, `sameSite: "strict"` or `"lax"`.

## Deserialization / Parsing

- `JSON.parse` on attacker data — prototype pollution if downstream code uses `obj[key]`. Look for merge/clone util uses on parsed data.
- `js-yaml` — `yaml.load(input)` (unsafe in pre-4.x) vs `yaml.safeLoad`. Default is safe in 4.x.
- `xml2js` — XML XXE possible if `explicitCharkey` + DTD enabled. Default is safe.
- `serialize-javascript` for SSR — use `{ unsafe: false }` (default).

## Process / Filesystem

- `child_process.exec(cmd)` with concat = command injection.
- `child_process.execFile(file, args)` safer if `args` is array.
- `fs.readFile(path.join(base, userPath))` — `..` traversal possible. Resolve and check `path.resolve(full).startsWith(base)`.

## Supply Chain

- `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` missing in committed code = unpinned deps.
- `postinstall` scripts in deps run on install. Audit for unknown packages.
- `node_modules` committed — bizarre, flag.
- Typosquats: `lodash` vs `lodahs`, `chalk` vs `chaIk` (capital I).
- `npm audit` output — only flag deps with reachable code paths.

## XSS Sinks (Universal Web)

- `innerHTML` / `outerHTML` / `insertAdjacentHTML` with user content
- `document.write` / `document.writeln`
- `eval`, `Function()`, `setTimeout(string)`, `setInterval(string)`
- `dangerouslySetInnerHTML` (React)
- `v-html` (Vue)
- `[innerHTML]` (Angular bypassing sanitizer)
- `bypassSecurityTrust*` (Angular)
- Header injection via `Location: <user>` enabling status-code-controlled gadgets

## CSRF Patterns

- Cookie auth + state-changing GET — pretty bad.
- Cookie auth + JSON POST without preflight-triggering header — verify framework adds CSRF token or requires custom header.
- SameSite=Lax does NOT protect top-level POST navigations from forms.
