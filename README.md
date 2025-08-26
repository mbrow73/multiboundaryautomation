# Firewall Automation API: Usage & Prerequisites

This document explains how to use the **repository dispatch API** to create, update and remove firewall rules in the `multiboundaryautomation` repository.  It assumes you already have the automation workflows (`repo_api_config.yml`, `firewall_issue_builder.py`, `firewall_request_validator.py`, etc.) configured in the repository.

## 1. Prerequisites

1. **PAT or GitHub App Token**  
   The workflow is triggered via GitHub’s `repository_dispatch` API.  To call it you need a *Personal Access Token* (PAT) or a GitHub App installation token with at least:

   - `contents:write`  (to create issues)
   - `issues:write`    (to label and close issues)

   The token must be stored somewhere safe (e.g. in a secret or your local environment).

## 2. Calling the API

### 2.1. Endpoint

Send an HTTP `POST` request to:

```
https://api.github.com/repos/<owner>/<repo>/dispatches
```

Replace `<owner>/<repo>` with `mbrow73/multiboundaryautomation`.

### 2.2. Headers

Include the following headers:

```http
Authorization: Bearer <YOUR_TOKEN>
Accept: application/vnd.github+json
Content-Type: application/json
```

### 2.3. Payload structure

The JSON body must have two top‑level keys:

- `event_type`: one of `firewall_request`, `firewall_update`, or `firewall_remove`.
- `client_payload`: an object containing the request parameters.

#### 2.3.1. New rule requests (`firewall_request`)

The `client_payload` for a new rule request contains:

- **reqid** (string): must match `REQ` followed by 7–8 digits.
- **carid** (string): exactly 9 digits.
- **tlmid** (string): optional third‑party identifier (can be empty).
- **rules** (array): one or more rule objects.

Each rule object must include:

- **src** (string): comma‑separated list of source IPs or CIDRs.  Required.
- **dst** (string): comma‑separated list of destination IPs or CIDRs.  Required.
- **ports** (string): comma‑separated list of port numbers or ranges.  Required.
- **protocol** (string): one of `tcp`, `udp`, `icmp` or `sctp`.  Required.
- **justification** (string): brief business justification.  Required.

Example:

```json
{
  "event_type": "firewall_request",
  "client_payload": {
    "reqid": "REQ1234567",
    "carid": "123456789",
    "tlmid": "",
    "rules": [
      {
        "src": "10.0.0.1/32,10.0.0.2/32",
        "dst": "10.1.0.0/24",
        "ports": "443,8443",
        "protocol": "tcp",
        "justification": "Example rule",
      },
      {
        "src": "172.16.0.0/24",
        "dst": "192.168.1.10/32",
        "ports": "80",
        "protocol": "tcp",
        "justification": "Another rule"
      }
    ]
  }
}
```

#### 2.3.2. Rule update requests (`firewall_update`)

Updates require a new request ID (one you haven’t used before) and a list of rule modifications.  The `client_payload` must include:

- **new_reqid** (string): a fresh request ID (format `REQ` + 7–8 digits).
- **tlmid** (string): optional third‑party identifier.
- **rules** (array): each entry must specify the **current_name** of the rule to update plus at least one field beginning with `new_`.

Valid `new_` fields:

- `new_src` – new comma‑separated source IPs/CIDRs.
- `new_dst` – new comma‑separated destination IPs/CIDRs.
- `new_ports` – new comma‑separated port list.
- `new_protocol` – new protocol (`tcp`, `udp`, `icmp`, `sctp`).
- `new_carid` – new 9‑digit CARID.
- `new_justification` – updated business justification.

Example:

```json
{
  "event_type": "firewall_update",
  "client_payload": {
    "new_reqid": "REQ2000001",
    "tlmid": "",
    "rules": [
      {
        "current_name": "AUTO-REQ1234567-123456789-TCP-443,8443-1",
        "new_src": "10.0.0.5/32",
        "new_dst": "10.1.1.0/24",
        "new_ports": "8443",
        "new_protocol": "tcp",
        "new_carid": "987654321",
        "new_justification": "Updated justification"
      },
      {
        "current_name": "AUTO-REQ1234567-123456789-TCP-80-2",
        "new_ports": "8080",
        "new_justification": "Change to port 8080"
      }
    ]
  }
}
```

*At least one `new_` field must be specified for each rule.*  The helper script will generate a Markdown update request that your existing update workflow can process.

#### 2.3.3. Rule removal requests (`firewall_remove`)

The payload for removals has:

- **reqid** (string): the original request ID whose rules you want to remove.
- **rules** (array): a list of rule names to delete.  These names must exactly match the auto‑generated names (`AUTO-…`).

Example:

```json
{
  "event_type": "firewall_remove",
  "client_payload": {
    "reqid": "REQ1234567",
    "rules": [
      "AUTO-REQ1234567-123456789-TCP-443,8443-1",
      "AUTO-REQ1234567-123456789-TCP-8443-2"
    ]
  }
}
```

## 3. Notes and limitations

- **Payload size**: The entire `client_payload` must fit within GitHub’s `repository_dispatch` limit (about 64 KB).  If you need to submit hundreds of rules with long IP lists, consider splitting them into multiple dispatches or summarising IPs before sending.

- **No file attachments**: The dispatch API only accepts JSON.  You cannot attach arbitrary files.  If you need to use a large external file (e.g. an address list), commit it to the repository and then reference it in your automation scripts, or extend the helper to read from a URL.  At present the helper script expects everything in `client_payload.rules`.

- **Validation**: Submissions will be validated by `firewall_request_validator.py` or `firewall_rule_updater.py`.  Invalid REQIDs, CARIDs, ports, protocols, or IP formats will cause the issue to be closed automatically.

- **PR creation**: After validation and boundary mapping, the workflows create a pull request containing the generated Terraform `.auto.tfvars.json` file(s).  Once approved and merged, the firewall rules will be applied.

## 4. Example `curl` commands

Assuming you have saved your payload as `payload.json` and your PAT in an environment variable `$GH_TOKEN`, the following command triggers a new request:

```bash
curl -X POST \
  -H "Authorization: Bearer $GH_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  -H "Content-Type: application/json" \
  https://api.github.com/repos/mbrow73/multiboundaryautomation/dispatches \
  -d @payload.json
```

You can use the same endpoint for updates and removals by changing `event_type` and the payload structure.

