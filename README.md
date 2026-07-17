# param-miner

Find **hidden / unlinked HTTP parameters** an endpoint secretly accepts (arjun-style).

You point it at a URL you are allowed to test. It baselines the response (including a
**noise floor** from two identical junk-param requests), then probes a wordlist with a
unique **canary** value per parameter.

| Confidence | Rule |
|------------|------|
| **HIGH** | Canary reflected in body or a response header — param is clearly read |
| **MEDIUM** | Status changes, or body length moves **beyond the noise floor** (behaviour change) |
| *(ignore)* | Within noise — not a finding |

Authorised recon only. Stdlib Python 3.

## Install / run

```bash
cd param-miner
python3 param-miner.py -h
python3 -m param_miner -h
```

## Examples

```bash
# GET with built-in ~150-param wordlist
python3 param-miner.py 'http://127.0.0.1:18350/'

# POST form
python3 param-miner.py -u 'http://127.0.0.1:18350/' -X POST

# POST JSON
python3 param-miner.py -u 'http://127.0.0.1:18350/' -X POST \
  --content-type application/json

# Custom wordlist + JSON output
python3 param-miner.py -u 'http://target/api' -w myparams.txt --json
```

## Options

```
-u / URL              Target
-X GET|POST           Method (default GET)
--content-type        form-urlencoded or JSON (POST)
-w / --wordlist       Override built-in list
--workers N           Thread pool (default 10, max 10)
--timeout SEC         Per-request (default 8)
-k                    Skip TLS verify
-H 'Name: value'      Extra headers
--json                Machine-readable
```

## Lab

```bash
python3 vuln_app.py --port 18350   # reflects name; debug=1 changes page
python3 safe_app.py --port 18351   # constant response (must be silent)

python3 param-miner.py 'http://127.0.0.1:18350/'
# expect HIGH on name, MEDIUM on debug

python3 param-miner.py 'http://127.0.0.1:18351/'
# expect no findings
```

Or: `bash run_proofs.sh`

## Design notes

- **Noise floor** = abs(len(req1) − len(req2)) on identical junk-param probes. Length
  signals must exceed that floor.
- Pure content-hash flips **within** the floor are ignored (anti cry-wolf on dynamic pages).
- One request per candidate param; `ThreadPoolExecutor` capped at 10 workers.

## License

Authorised use / training. No AI attribution.
