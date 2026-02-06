# Helm Vault Inject

A **Helm post-renderer plugin** that injects secrets from HashiCorp Vault into rendered Kubernetes manifests. It is an alternative to [sh-helm-vault](https://github.com/shizacat/sh-helm-vault) with a different approach: processing happens **per rendered manifest** (document-by-document) and **after** Helm has already rendered the chart. Functionally it offers the same Vault integration (path templating, KV v1/v2, mount point, etc.), but the workflow and trade-offs differ.

## How It Differs from sh-helm-vault

| Aspect | sh-helm-vault | helm-vault-inject |
|--------|----------------|-------------------|
| **When** | Before/during Helm: decrypts values files, then runs Helm | After Helm: runs on the final rendered manifest stream |
| **What it sees** | Values files (e.g. `values.yaml`) | Rendered YAML (all resources Helm produced) |
| **Processing** | File-based (enc/dec/view/edit on value files) | Stream-based, document-by-document (each YAML doc in the manifest) |
| **Usage** | Wrapper commands (`helm vault template`, `helm vault install`, etc.) | Used as `--post-renderer` with standard `helm template` / `helm install` / `helm upgrade` |

## Advantages of the Post-Render Approach

- **No decrypted files on disk** — No `.dec.yaml` files; no `clean` step. Secrets are injected only in memory when producing the final manifest.
- **Simpler CI/CD** — Use normal `helm template` / `helm install` / `helm upgrade` and pass a single post-renderer binary; no wrapper scripts to decrypt values and clean up.
- **Clear separation** — Helm is responsible only for templating; this plugin is responsible only for replacing Vault references in the result.
- **Works with any chart** — As long as the **rendered** output contains `VAULT:...` placeholders (from values or from chart templates), they will be replaced. No need to pre-process values files.

## Limitations

- **No enc/dec/view/edit/clean** — There are no commands to encrypt/decrypt or edit value files. You manage `VAULT:...` placeholders in your values or templates and rely on the post-renderer to inject secrets at render time.
- **Requires `--post-renderer`** — Every relevant Helm command must be called with the post-renderer (e.g. `helm template ... --post-renderer ./path/to/vault-injector` or the plugin’s post-renderer hook).
- **Secrets only in final manifest** — Placeholders must appear in the **rendered** YAML. If your chart or values never output `VAULT:...` strings into the manifests, nothing will be replaced.
- **Stream-based** — The plugin reads one combined manifest stream from stdin and writes the result to stdout; it does not read or write individual files on disk.

## Requirements

- Python 3.7+
- [hvac](https://pypi.org/project/hvac/) (Vault client)
- [ruamel.yaml](https://pypi.org/project/ruamel.yaml/)
- HashiCorp Vault (address and token via environment)
- Helm 3 with post-renderer support

## Installation

1. Install Python dependencies:

   ```bash
   pip install hvac ruamel.yaml
   ```

2. Install the Helm plugin (post-renderer):

   ```bash
   helm plugin install https://github.com/shizacat/helm-vault-inject
   ```

## Usage

Use the plugin as a **post-renderer** so that Helm passes the rendered manifest to it; the script reads stdin and writes the modified manifest to stdout.

### Environment variables

**Vault client (hvac):**

| Variable | Description |
|----------|-------------|
| `VAULT_ADDR` | Vault HTTP(S) address (e.g. `http://localhost:8200`) |
| `VAULT_TOKEN` | Token for Vault authentication |
| `VAULT_NAMESPACE` | Optional Vault namespace (Enterprise) |

**Plugin (optional, defaults in parentheses):**

| Variable | Default | Description |
|----------|---------|-------------|
| `HELM_VAULT_MOUNT_POINT` | `secret` | KV secrets engine mount point |
| `HELM_VAULT_TEMPLATE` | `VAULT:` | Prefix for placeholders (e.g. `VAULT:/path/to/secret.key`) |
| `HELM_VAULT_DELIMINATOR` | `changeme` | Legacy deliminator (used with template) |
| `HELM_VAULT_KVVERSION` | `v2` | KV engine version: `v1` or `v2` |
| `HELM_VAULT_ENVIRONMENT` | (empty) | Substituted for `{environment}` in paths |

### Vault path templating

In your **values** or **chart templates**, use placeholders like:

```yaml
password: VAULT:/myapp/db.password
apiKey: VAULT:/myapp/api.key.2
```

- Path format: `VAULT:/path/to/secret.key` or `VAULT:path/to/secret.key`
- Optional **version** (KV v2): use a trailing `.&lt;version&gt;` (e.g. `.2` for version 2)
- To include a literal dot in path or key, double it (e.g. `key..name`)
- If `HELM_VAULT_ENVIRONMENT` is set, `{environment}` in the path is replaced (e.g. `VAULT:/myapp/{environment}/db.password`)

Your chart should render these values into the Kubernetes manifests so that the **output** of `helm template` (or install/upgrade) contains these strings. The post-renderer then replaces them with values read from Vault.

### Running Helm with the post-renderer

**Template (stdout):**

```bash
export VAULT_ADDR=http://vault:8200 VAULT_TOKEN=...
helm template myrelease ./mychart -f values.yaml --post-renderer vault-injector
```

**Install / upgrade:**

```bash
helm install myrelease ./mychart -f values.yaml --post-renderer vault-injector
helm upgrade myrelease ./mychart -f values.yaml --post-renderer vault-injector
```

The exact post-renderer command depends on how the plugin registers itself (see `plugin.yaml`). Typically you pass the plugin name or the path to the script that reads stdin and writes the injected manifest to stdout.

## Development

```bash
# Dependencies
pip install -e ".[dev]"

# Tests
pytest
```

## License

See [LICENSE](LICENSE).
