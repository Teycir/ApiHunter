---
author: teycir ben soltane
email: teycir@pxdmail.net
website: teycirbensoltane.tn
last_updated: 2026-03-14
tags: [index, documentation, guide, navigation]
category: Documentation Index
---

# 📚 ApiHunter Documentation Index

Complete guide to ApiHunter documentation and resources.

## Quick Navigation

### 📖 Core Documentation

| Document | Category | Purpose |
|----------|----------|---------|
| [README.md](../Readme.md) | Getting Started | Project overview, features, quick start, and CLI reference |
| [Architecture](./architecture.md) | Technical Documentation | System design, data flow, and key invariants |
| [Configuration](./configuration.md) | Configuration Guide | CLI parameters and configuration options |
| [Scanners](./scanners.md) | Scanner Modules | Detection capabilities for each scanner module |

### 📋 Additional Resources

| Document | Location | Purpose |
|----------|----------|---------|
| **HOWTO** | [HOWTO.md](../HOWTO.md) | Detailed usage guide and examples |
| **Changelog** | [Changelog.md](../Changlog.md) | Version history and updates |
| **License** | [Licence](../Licence) | MIT License information |
| **Deep Review Checklist** | [deep-review-checklist.md](./deep-review-checklist.md) | Tracked checklist from the latest code review |

---

## Documentation by Tag

### Security Scanning
- [README.md](../Readme.md) - `security, scanner, api`
- [Scanners](./scanners.md) - `cors, csp, graphql, api-security`

### Technical Design
- [Architecture](./architecture.md) - `architecture, design, modules, async-runtime`
- [Configuration](./configuration.md) - `configuration, cli, settings, parameters`

### Development
- [Architecture](./architecture.md) - `async-runtime`
- [HOWTO.md](../HOWTO.md) - Usage guide and development

---

## Documentation by Category

### Getting Started
1. [README.md](../Readme.md) - Start here
2. [HOWTO.md](../HOWTO.md) - Detailed setup and usage
3. [Configuration.md](./configuration.md) - CLI options reference

### Technical Deep Dive
1. [Architecture.md](./architecture.md) - System design
2. [Scanners.md](./scanners.md) - Scanner modules detail
3. [Configuration.md](./configuration.md) - Configuration options

---

## Key Concepts

### Scanner Modules
- **CORS** - Cross-Origin Resource Sharing security checks
- **CSP** - Content Security Policy validation
- **GraphQL** - GraphQL endpoint security analysis
- **API Security** - General API hardening checks
- **JWT** - Token inspection and weak-signature checks

### Configuration Areas
- **URLs & Targets** - Target specification and discovery
- **Performance** - Concurrency and timeout settings
- **Network** - Proxy, TLS, and politeness controls
- **Output** - Report generation and formatting

### Architecture Components
- **Discovery** - URL normalization and deduplication
- **HttpClient** - Request handling with WAF evasion
- **Scanner** - Pluggable security checking trait
- **Reporter** - NDJSON output generation

---

## Author Information

**Author:** teycir ben soltane  
**Email:** teycir@pxdmail.net  
**Website:** teycirbensoltane.tn  
**Last Updated:** 2026-03-14

---

## Documentation Stats

- **Total Documents:** 5 core documents (+ HOWTO, Changelog, License)
- **Scanner Modules:** 5 built-in scanners
- **Configuration Parameters:** 16+ options
- **Exit Codes:** 4 different exit codes

---

## Getting Help

1. **Quick Start:** See [README.md](../Readme.md) features and CLI reference
2. **Installation:** See [HOWTO.md](../HOWTO.md) for setup instructions
3. **Configuration:** See [Configuration.md](./configuration.md) for all CLI options
4. **Troubleshooting:** Check [HOWTO.md](../HOWTO.md) for common issues
5. **Scanner Details:** See [Scanners.md](./scanners.md) for detection details

---

## Document Format

All documentation follows this metadata format:
```yaml
---
author: teycir ben soltane
email: teycir@pxdmail.net
website: teycirbensoltane.tn
last_updated: YYYY-MM-DD
tags: [tag1, tag2, tag3]
category: Documentation Category
---
```

This ensures consistency and enables better document discovery and organization.
