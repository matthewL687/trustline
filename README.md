# Trustline

Trustline audits the external trust boundary in a codebase. It inventories outside hostnames and storage URLs, gathers registration and availability evidence, and ranks what deserves a closer look.

The repository includes a static GitHub Pages site and a Python command-line scanner. The site opens with one public website link field and returns a report of DNS, CAA, DMARC, RDAP registration, and HTTPS signals, with direct links to certificate transparency and archived-history records. No terminal or sign-in is required to check a public site.

A public website URL does not expose its source code, API configuration, private pages, or deployment files. The hosted report therefore checks public domain signals; it cannot inventory code references like the repository scanner. Use the CLI below to scan a local codebase for references with file context, storage URLs, and deployment configuration.

## Run a live scan

```sh
python3 trustline.py /path/to/repository
```

For machine-readable output:

```sh
python3 trustline.py /path/to/repository --json > trustline-report.json
```

For a local, no-network inventory only:

```sh
python3 trustline.py /path/to/repository --no-network
```

The scanner searches text files (up to 2 MB each) and skips common generated and dependency folders. It classifies each reference by surrounding code and file context. Network checks query RDAP, DNS, certificate transparency (crt.sh), and Wayback CDX; cloud storage references also receive a conservative HTTP probe. External evidence is cached in SQLite for 24 hours under `~/.cache/trustline/evidence.sqlite3` by default. Set `--cache /path/to/cache.sqlite3` to choose a different location.

All registry, DNS, and HTTP facts come from deterministic lookups. The built-in severity scoring is also deterministic. To ask Muse Spark to refine the reference classification and risk explanation, set a Meta Model API key:

```sh
export MODEL_API_KEY="your-key"
python3 trustline.py /path/to/repository --json
```

The integration uses the Meta Model API's OpenAI-compatible chat completions endpoint and `muse-spark-1.3` by default. Change the model with `TRUSTLINE_MODEL`. Model output is validated against allowed category and severity values; it cannot change evidence, dates, DNS state, or bucket results. If the API call fails, deterministic results remain available. See the [Meta Model API documentation](https://dev.meta.ai/docs/overview) for access and current API details.

## GitHub Pages

The site is in the repository root. To publish it, create a GitHub repository and push this folder, then go to **Settings → Pages** and select **GitHub Actions** as the source. The included workflow publishes the site on pushes to `main`.

The hosted site starts with a website link form and opens a detailed report after a check. It uses browser-accessible public lookups and links directly to certificate transparency and Wayback history; cross-origin browser restrictions limit which external services can return data directly to the report.

## What the scanner checks

- Hostname registration and expiry through RDAP
- DNS resolution status
- S3-style `NoSuchBucket` responses when a storage URL is detected
- Certificate Transparency records from crt.sh
- Archived URL snapshots from the Wayback Machine CDX API
- Runtime context, reference type, severity, remediation, and uncertainty

RDAP, DNS, CT, and archive signals can be incomplete or temporarily unavailable. A missing DNS answer or `NoSuchBucket` response is evidence to verify, not proof by itself that a name is available to register. Review high-impact findings before taking action.

## Repository layout

- `index.html`, `styles.css`, `app.js`: GitHub Pages dashboard
- `trustline.py`: local reference inventory and investigation CLI
- `.github/workflows/pages.yml`: static Pages deployment

## License

MIT. See [LICENSE](LICENSE).
