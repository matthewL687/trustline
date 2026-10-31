# Trustline

Trustline audits the external trust boundary in a codebase. It inventories outside hostnames and storage URLs, gathers registration and availability evidence, and ranks what deserves a closer look.

The repository includes a static GitHub Pages product site and a Python command-line scanner. The site is an interactive sample dashboard. Run the scanner locally for a live audit; a static Pages site cannot safely hold a model API key or perform server-side repository scans.

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

The site is in the repository root. The included workflow publishes it automatically on pushes to `main`. If needed, go to **Settings → Pages** and select **GitHub Actions** as the source.

The dashboard includes sample findings to show the report design. It does not imply that the displayed example scan was run against your repository. The **Run new scan** button explains how to run a real local scan.

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
