# Language Patterns — Java / JVM

Spring, Jakarta EE, Hibernate, Jackson, JAXB, plain Java SE.

## Spring-Specific Hot Spots

### spring-expression (SpEL)

- `SpelExpressionParser` taking user input — RCE primitive.
- `T(java.lang.Runtime).getRuntime().exec(...)` is the canonical payload.
- Spring4Shell (CVE-2022-22965) lineage — class-loader access via `class.protectionDomain.classLoader`.
- Look for: error message construction with user fields, parameter resolution annotations, `@Value` on user-facing strings.

### spring-web

- **CORS:** `CorsConfiguration.setAllowedOriginPatterns()` — pattern compiled with `Pattern.quote` then `*` swapped to `\E.*\Q`. Verify the matcher is full-anchor, not partial.
- **Multipart:** `MultipartResolver` — verify max sizes set, verify temp dir not world-readable.
- **Forwarded headers:** `ForwardedHeaderFilter` — trust boundary. Only enable behind a trusted proxy.
- **Path matching:** `useSuffixPatternMatch` deprecated for security. Verify it's off.
- **HiddenHttpMethodFilter:** lets POST become PUT/DELETE via `_method`. Auth checks must happen after this filter.

### spring-oxm / spring-web XML parsers

XXE checklist — every parser must be hardened:

```java
// SAXParserFactory
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
factory.setXIncludeAware(false);
factory.setNamespaceAware(true);

// DocumentBuilderFactory — same features.
// XMLInputFactory:
factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);

// TransformerFactory:
factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

// SchemaFactory: same as TransformerFactory.
```

Common bug: one parser hardened, another in same class not. `Jaxb2Marshaller` historically had `schemaParserFactory` and `sourceParserFactory` configured separately.

### spring-jdbc

- **Identifier quoting:** `JdbcTemplate.queryForObject(...)` uses `?` for values. Identifiers (table names, column names) are not parameterizable — concatenated. If identifier comes from user input, that's SQL injection.
- `NamedParameterJdbcTemplate` — same rule.
- `SimpleJdbcInsert` — column list comes from metadata, but if developer passes user-supplied column names → injection.

### spring-data-jpa

- `@Query(nativeQuery = true)` with string concat → SQL injection.
- JPQL with concat → JPQL injection (still bad).
- `Sort` parameter from request — `Sort.by(direction, property)` where property comes from request: validate against allowlist or attacker injects ORDER BY clauses with subqueries.
- `Specification` and Criteria: usually safe.
- Method-name queries: safe.

### spring-messaging / WebSocket / SockJS

- `@MessageMapping` endpoints — verify auth via `Principal` or interceptor.
- SockJS session lifecycle: session created BEFORE origin check is the bug pattern.
- STOMP CONNECT frame: verify auth at CONNECT, not just per-message.
- Broker relay: don't expose internal broker without auth.

### Spring Security

- `@PreAuthorize` / `@PostAuthorize` — only works on Spring beans. Direct `new` bypasses.
- `permitAll()` on a path that prefixes a sensitive route via Ant matcher (`/api/**` permits everything underneath).
- `csrf().disable()` — only safe for stateless APIs with token-based auth.
- `frameOptions().disable()` — clickjacking surface.
- `OAuth2LoginConfigurer` redirect URI matching — wildcard subdomain is a takeover.

### Jackson

- `enableDefaultTyping()` — gadget chain RCE. Banned since 2.10 by default but custom `ObjectMapper` configs revive it.
- `@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)` on broad polymorphic types — same problem.
- `PolymorphicTypeValidator` configured to allow broad packages.
- `ObjectMapper.readValue()` on attacker JSON for a class with side-effect setters.

### Hibernate / JPA

- `Session.createNativeQuery` with concat — SQL injection.
- `criteriaBuilder.equal(root.get(field), value)` where `field` comes from user → field name injection (less severe but still bad on entities with sensitive columns).
- `@Filter` definitions with concat.

### JAXB

- `JAXBContext.newInstance` is fine; `Unmarshaller.unmarshal` on untrusted XML without securing the SAX/StAX factory underneath is XXE.

## Java Native Deserialization

- `ObjectInputStream.readObject()` on attacker bytes = RCE if any deserialization gadget is on the classpath (commons-collections, snakeyaml, spring-aop).
- `@RestController` reading `application/x-java-serialized-object` is the obvious sink.
- Less obvious: RMI ports, JMX, JNDI lookups, MQ message consumers.
- Filter via `ObjectInputFilter` (Java 9+) or banned outright.

## SnakeYAML

- `new Yaml().load(input)` on attacker input — uses `Constructor` allowing arbitrary class instantiation. Pre-2.x default was unsafe; 2.0+ defaults to `SafeConstructor`.
- `yaml.loadAs(input, MyClass.class)` — still risks property-based gadgets.
- Use `new Yaml(new SafeConstructor(new LoaderOptions()))`.

## Spring Boot Actuator

- `/actuator/env` — env vars including secrets if exposed.
- `/actuator/heapdump` — full heap, secrets visible.
- `/actuator/jolokia` (if present) — JMX over HTTP, RCE.
- `/actuator/loggers` — POST changes log level, no auth = pre-auth log noise.
- `management.endpoints.web.exposure.include=*` is the trigger.

## Servlet / Filter Chain

- Path normalization differences between filter and dispatcher — auth filter sees `/admin/foo` but dispatcher routes `/admin//foo` differently. Less common in modern Spring but legacy code.
- `RequestDispatcher.forward` re-runs filters or doesn't depending on dispatcher type config.

## Common False Positives (REJECT material)

- `String.format("WHERE id=%d", id)` where `id` is `long` typed — not injectable in Java.
- `Runtime.exec(new String[]{"sh", "-c", cmd})` where `cmd` is a constant.
- `new File(user)` where `user` is constrained by upstream check.
- ORM-internal SQL builders that look concat-y but use bind parameters under the hood.

## Build Files

- `pom.xml` / `build.gradle`: pinned versions of crypto/parser libs.
- Repository declarations: ensure private repos resolve before public (dependency confusion).
- `<systemProperties>` in surefire/failsafe — secrets here leak to logs.

## Versions to Flag (April 2026)

- Spring Framework < 6.1 (5.x EOL Aug 2024) — file as supply chain finding.
- Jackson < 2.16 — multiple polymorphic typing CVEs.
- log4j-core < 2.17.1 — Log4Shell + variants.
- snakeyaml < 2.0 — CVE-2022-1471 (default constructor).
- Apache Commons Text < 1.10 — CVE-2022-42889 (StringSubstitutor).
- Apache HttpClient < 5.2 — various CVEs.
- Tomcat < 10.1.x latest — depends on version line.
- Spring Cloud Function < 3.2.3 — Spring4Shell variant.
