# Trustline

Trustline audits the external trust boundary in a codebase. The hosted site takes a public GitHub repository URL, reads the default branch, and inventories external hostnames and storage URLs in text files. Findings link back to the file and line where each reference appears.

With the included Cloudflare Worker connected, the report also gathers DNS and RDAP registration data, checks storage endpoints for strong dangling-bucket signals, queries Certificate Transparency and Wayback history, and ranks findings using reference context and potential blast radius. It explains uncertainty and gives a fix for each result. An optional Muse Spark review can refine classification and reasoning; it cannot replace deterministic evidence.

## Hosted site

Open [Trustline](https://matthewl687.github.io/trustline/) and paste a public GitHub repository URL. No terminal or GitHub sign-in is needed. The static site can inventory a repository without the Worker. Until the Worker is deployed and connected, the report explicitly marks live ownership evidence and agent review as unavailable; it does not present an inventory-only result as a complete audit.

## Enable the full evidence report

GitHub Pages is static hosting and cannot safely store API credentials. The optional Worker runs public evidence lookups server-side and keeps the model key out of the browser.

1. Create a Cloudflare account and open **Workers & Pages → Create application → Create Worker**.
2. Paste the contents of `trustline-worker.js` into the Worker editor and deploy it. Set the `ALLOWED_ORIGIN` variable to `https://matthewl687.github.io` in the Worker settings.
3. Optional: add a Worker secret named `META_MODEL_API_KEY` in Worker settings to enable Muse Spark review. You can also set `TRUSTLINE_MODEL`; the default is `muse-spark-1.3`.
4. Copy the deployed Worker URL. Edit `site-config.js` and set `window.TRUSTLINE_API_URL` to that URL, then commit. GitHub Pages will publish it.

The Worker only accepts requests from this GitHub Pages origin. It accepts public repository references, rate-limits parallel lookups per request, and only probes storage URLs recognized as AWS or Google Cloud storage. Model review is optional and deterministic evidence remains the source of factual claims. Do not put API credentials in `site-config.js` or any public repository file.

## Audit coverage and limits

- Public repository files on the default branch, including source, HTML, configuration, CI workflows, Dockerfiles, and documentation
- External HTTP(S), S3, and Google Storage references with filename, line, usage context, and a source link
- DNS resolution, RDAP registration and expiry, Certificate Transparency, and Wayback CDX snapshots
- Conservative S3 and Google Cloud storage endpoint probes
- Context-aware severity, explanation, recommended remediation, and uncertainty

The browser inventory skips common dependency/generated folders and binary files, and caps the scan at 220 files and 1.2 MB of text. GitHub's recursive tree API also limits very large repositories. Public records are point-in-time signals: DNS failures and provider error pages do not prove that a resource is available to claim. Private repositories are not supported. Dynamic references assembled at runtime, encrypted content, and references hidden in binary files may not be detected.

## Local scanner

The repository also includes a Python scanner for local codebases:

```sh
python3 trustline.py /path/to/repository
```

For JSON output, use `--json`; for extraction without network lookups, use `--no-network`. Optional Muse Spark review uses the `MODEL_API_KEY` environment variable. The local scanner is not required to use the hosted site.

## Repository layout

- `index.html`, `styles.css`, `app.js`, `site-config.js`: GitHub Pages interface and public repository inventory
- `trustline-worker.js`, `wrangler.toml`: secure evidence and optional reasoning service
- `trustline.py`: local codebase scanner
- `.github/workflows/pages.yml`: Pages publishing

## License

MIT. See [LICENSE](LICENSE).
