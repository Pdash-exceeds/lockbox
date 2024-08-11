# Lockbox

Lockbox is a forward proxy for making third party API calls.

## Why?

Automation or workflow platforms like [Zapier](https://zapier.com) and [IFTTT](https://ifttt.com) allow
"webhook" actions for interacting with third party APIs.

* [IFTTT webhooks](https://ifttt.com/maker_webhooks)
* [Zapier webhooks](https://zapier.com/apps/webhook/integrations)

They require you to provide your third party API keys so they can act on your behalf. You are trusting them to keep your
API keys safe, and that they do not misuse them.

<img src="/assets/lockbox_before.png" />

__May be you don't want that.__

## How Lockbox helps

You run your own Lockbox server.

When a workflow platform needs to make a third party API call on your behalf, it makes a Lockbox API call instead.
Lockbox makes the call to the third party API, and returns the result to the workflow platform.

<img src="/assets/lockbox_after.png" />

### Live demo
Proxy requests to Github API.

```bash

# Direct call to GitHub's API (public).
curl https://api.github.com/orgs/google/repos

# Call to GitHub API via Lockbox (public, uncredential'd, both legs)
curl https://lockbox-proxy-demo.fly.dev/s/github_public/orgs/google/repos

# Call to GitHub API (auth'd by Github API token) via Lockbox (auth'd by service token)
export SERVICE_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJsb2NrYm94IiwiZXhwIjoyNzA3Nzg4NjAyLCJzZXJ2aWNlX25hbWUiOiJnaXRodWJfcHJpdmF0ZV9iZWhpbmRfc2VydmljZV90b2tlbiIsImF1ZCI6ImxvY2tib3gtcHJveHktZGVtbyJ9.t3XNqQg-XkFeyziSb8xvVlCd7-TNac9hNScWuNX7dRo
curl https://lockbox-proxy-demo.fly.dev/s/github_private_behind_service_token/orgs/google/repos -v -H "Authorization: Bearer $SERVICE_TOKEN"
# - Curious about SERVICE_TOKEN?  Copy into https://jwt.io/ to decode it.
# - Underlying Github API token is used by Lockbox, but not exposed to the client (curl).

```

### Main benefits

* Third party API keys are never exposed to the workflow platform
* You can [audit](#auditing) all API calls made on your behalf
* [Planned] You can restrict access to external APIs in a more fine grained manner
* [Planned] Rate limit third party API calls

### Drawbacks

* You need to run an instance of Lockbox on your own infrastructure. You own its performance, security and reliability.
* Centralization of YOUR API credentials (with your Lockbox instance). However, consider this a different kind of
  centralization. I.e. Workflow automation platforms centralize credentials for a large number of users in a single
  system too, possibly presenting a valuable aggregate target for attackers.

## How to run Lockbox

### Installation

```bash
pip install lockbox-proxy
```

### Prepare a services config file

May be call it `sample_config.json`. Example:

```json5
{
  "services": {
    // Access GitHub APIs that do not require auth
    "github_public": {
      "base_url": "api.github.com",
      "requires_service_token": false
    },
    // Access GitHub APIs that do not require auth - except Lockbox requires auth (by "service token')
    "github_public_behind_service_token": {
      "base_url": "api.github.com",
      "requires_service_token": true
    }
  }
}
```

For reference, refer to [lockbox/config.py](https://github.com/mkjt2/lockbox/blob/main/lockbox/config.py).

### Choose a Lockbox secret key

This secret key is used to generate signed service tokens. Service tokens are used to authenticate API calls to Lockbox.

```bash
echo "YOUR_SUPER_SECRET_VALUE" > signing_key.txt
```

### Run Lockbox server

This snippet runs Lockbox server on `localhost:8000`.

```bash
# set config env vars
export LOCKBOX_SIGNING_KEY_FILE=signing_key.txt
export LOCKBOX_CONFIG_PATH=sample_config.json

# start the server
gunicorn lockbox.app:app --preload
```

## Accessing third-party APIs via Lockbox

Example: Call to GitHub API
to [list an organization's public repos.](https://docs.github.com/en/rest/repos/repos?apiVersion=2022-11-28#list-organization-repositories)

*Without Lockbox*, the request would have been `GET https://api.github.com/orgs/google/repos` for Google's repos.

### Configure `api.github.com` in service config file.

See example [above](#prepare-a-services-config-file).

### Generate a Lockbox service token

Each Lockbox service token allows access to a single service (e.g. `github_public_behind_service_token`).

This command generates a Lockbox service token that authorizes the bearer to access GitHub API through Lockbox.

The service token is saved to the `SERVICE_TOKEN` environment variable.

```bash
export SERVICE_TOKEN=$(python lockbox/generate_service_token.py \
    --service-name github_public_behind_service_token \
    --signing-key-file signing_key.txt \
    --audience walkthrough
    )
```

Note: `audience` identifies the intended recipient of the service token.

### Make the Lockbox API call

```bash
# Lockbox URL structure: /s/{service_name}/{path}
curl localhost:8000/s/github_with_auth/orgs/google/repos -v -H "Authorization: Bearer $SERVICE_TOKEN"
```

### How to revoke service tokens

Revocation is done through checking the `audience` claim of the service token.

In the service config file (e.g. `sample_config.json`), each service may specify a list of `audiences` that are valid:

```json5
{
  "services": {
    // Access GitHub APIs that DO require auth - and Lockbox requires auth (by "service token") to protect access to that.
    // Additionally, only service tokens with audience "zapier_webhook" will be accepted by Lockbox.
    "github_private_behind_service_token": {
      // ...
      // ...
      "requires_service_token": true,
      "valid_audiences": [
        "walkthrough"
      ]
    },
  }
}
```

* If `valid_audiences` is unset, or set to `null`, it means all audiences are valid.
* If `valid_audiences` is set to a list, then only audiences in the list are valid.

In the example above, only service tokens with audience `walkthrough` is valid for the service
`github_private_behind_service_token`.

To revoke ALL service tokens for a service, set `valid_audiences` to `[]`.

Note `sample_config.json` updates are not automatically reloaded. You need to restart Lockbox server for changes to
take.

### Auditing

Auditing can be enabled by setting `audit_log` in the config file.

```json5
{
  "services": {
    // ...
  },
  "audit_log": {
    "type": "local_dir",
    // Lockbox will try to create this directory if it does not exist
    "root_dir": "/var/tmp/lockbox_audit_log"
  }
}
```

Events are logged in JSON format to the file path: `<root_dir>/service_name/YYYY-MM-DD/HH-MM-SS-<uuid>.json`.

`<uuid>` ensures filename uniqueness for events logged within the same second.

## Design philosophy

This is very much a prototype implementation to explore the concept of abstracting out third party API calls. E.g. Is it
even a common need?

Therefore, the main priorities are:

* Correctness
* Simplicity (in configuration, usage)
* Security (avoid blatant shortcomings)
* Minimize to essential features only (which may evolve with feedback!)

We will consider other factors later, such as:

* Performance (e.g. may be not Python?)
* Flexibility
* Deployment scripts / walkthroughs

## Alternatives / Prior art

* Nginx - battle testing web server, which can be configured to behave like Lockbox. Especially with various scripting
  options. E.g.
    * [OpenResty / Nginx with Lua](https://openresty.org/)
    * [Njs scripting](https://nginx.org/en/docs/njs/)
 
## Exceeds Specifics

* Update github_private_behind_service_token.credential.token to a valid PAT in sample_config.json
* Generate a new service token :
 `export SERVICE_TOKEN=$(python generate_service_token.py \
    --service-name github_private_behind_service_token \
    --signing-key-file signing_key.txt \
    --audience walkthrough
    )`
* export LOCKBOX_CONFIG_PATH to sample_config.json
* export LOCKBOX_SIGNING_KEY_FILE to signing_key.txt (update contents to new value with `openssl rand -base64 32`)
* Run `python run.py` or `gunicorn -w 4 -b 0.0.0.0:8000 run:app` 

