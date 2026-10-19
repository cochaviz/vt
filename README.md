# vt

A small command-line client for VirusTotal, built on [vt-go](https://github.com/VirusTotal/vt-go) and cobra.

```sh
go install github.com/cochaviz/vt/cmd/vt@latest
# or from a checkout:
make build              # ./bin/vt   (or: make install)
vt config set api_key   # prompts, so the key stays out of shell history
```

The API key is read from `--api-key`, then `VT_API_KEY`, then the config file
(`vt config path`; override with `VT_CONFIG`).

## Commands

| Command    | What it does |
|------------|--------------|
| `get`      | Report for hashes, URLs, domains or IPs (type auto-detected); `-e` lists flagging engines, `-a` picks attributes |
| `lookup`   | One line per argument: known/unknown + detections; `--unknown`/`--known` for filtering |
| `download` | Password-protected zip by default (`infected`); `--raw` for unpacked files (premium) |
| `upload`   | Upload files/directories; skips files VT already knows unless `--force`; `--wait` for verdicts |
| `scan`     | Reanalyse a known file by hash, or scan a URL; `--wait` |
| `analysis` | Show/wait on an analysis ID |
| `search`   | VT Intelligence search (premium); `--ids` for piping |
| `related`  | Follow a relationship, e.g. `contacted_domains`, `dropped_files` |
| `config`   | `show`, `get`, `set`, `unset`, `path` |
| `version`  | Build information |

Global flags: `--json` (raw API objects), `--no-progress`, `--api-key`.

Commands that take hashes read them from stdin with `-` or when piped:

```sh
sha256sum samples/* | cut -d' ' -f1 | vt lookup --unknown
vt search --ids 'type:peexe p:20+ fs:1d-' | vt download -O today.zip
vt related evil.example communicating_files --ids | vt get -a type_tag
```
