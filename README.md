# ExternalDNS Webhook Provider for OPNsense

<div align="center">

[![GitHub Release](https://img.shields.io/github/v/release/KittyKatt/external-dns-opnsense-bind-webhook?style=for-the-badge)](https://github.com/KittyKatt/external-dns-opnsense-bind-webhook/releases)

</div>

This webhook graciously ~~stolen from~~ inspired by [crutonjohn's OPNSense Unbound Webhook](https://github.com/crutonjohn/external-dns-opnsense-webhook) (which in turn was inspired by [Kashall's Unifi Webhook](https://github.com/kashalls/external-dns-unifi-webhook)).

> [!WARNING]
> This software is experimental and **NOT FIT FOR PRODUCTION USE!**

[ExternalDNS](https://github.com/kubernetes-sigs/external-dns) is a Kubernetes add-on for automatically managing DNS records for Kubernetes ingresses and services by using different DNS providers. This webhook provider allows you to automate DNS records from your Kubernetes clusters into your OPNsense Firewall's `os-bind` plugin.

## 🗒️ Important Notes

As of this writing this webhook supports A, AAAA, and absolute FQDN CNAME records using the BIND plugin's API.

## 🚫 Limitations

* As mentioned above, with CNAME records this only works when the target of our record is an absolute FQDN. Relative targets like "beep" or "beep.boop" will not work. Future work may make this possible, but right now I haven't figured out how to determine what to do with a relative target and how to handle it.
* This does not support either TXT or DynamoDB registry.

### A Note About Manually Created Records

> [!WARNING]
> If you don't follow this, **manually entered A/AAAA/CNAME records can be permanently destroyed**

If you have records that are managed manually or by some process other than this webhook and you intend for those records to share a domain, then you must use `policy=upsert-only` or `policy=create-only` with your ExternalDNS deployment. If you use `policy=sync`, this will attempt to reconcile the zone by deleting all A/AAAA/CNAME records not currently defined by a supported ExternalDNS source in-cluster.

A future iteration of this provider will support TXT registry, which should allow you to use `policy=sync` and only manage records that have corresponding TXT entries representing ownership by this provider.

<!-- ## 🎯 Requirements
# unknown at the moment
- ExternalDNS >= v0.14.0
- OPNsense >= 23.7.12_5 -->

## ⛵ Deployment

1. Create a local user with a password in your OPNsense firewall. `System > Access > Users`

2. Create an API keypair for the user you created in step 1.

3. Create (or use an existing) group to limit your user's permissions. The known required privileges are:

* `Services: BIND`
* `Status: Services`

1. Add the ExternalDNS Helm repository to your cluster.

    ```sh
    helm repo add external-dns https://kubernetes-sigs.github.io/external-dns/
    ```

2. Create a Kubernetes secret called `external-dns-opnsense-secret` that holds `api_key` and `api_secret` with their respective values from step 1:

    ```yaml
    apiVersion: v1
    stringData:
      api_secret: <INSERT API SECRET>
      api_key: <INSERT API KEY>
    kind: Secret
    metadata:
      name: external-dns-opnsense-secret
    type: Opaque
    ```

3. Create the helm values file, for example `external-dns-webhook-values.yaml`:

    ```yaml
    fullnameOverride: external-dns-opnsense
    logLevel: debug
    provider:
      name: webhook
      webhook:
        image:
          repository: ghcr.io/KittyKatt/external-dns-opnsense-bind-webhook
          tag: main # replace with a versioned release tag
        env:
          - name: OPNSENSE_API_SECRET
            valueFrom:
              secretKeyRef:
                name: external-dns-opnsense-secret
                key: api_secret
          - name: OPNSENSE_API_KEY
            valueFrom:
              secretKeyRef:
                name: external-dns-opnsense-secret
                key: api_key
          - name: OPNSENSE_HOST
            value: https://192.168.1.1 # replace with the address to your OPNsense router
          - name: OPNSENSE_SKIP_TLS_VERIFY
            value: "true" # optional depending on your environment
          - name: LOG_LEVEL
            value: debug
        livenessProbe:
          httpGet:
            path: /healthz
            port: http-webhook`
          initialDelaySeconds: 10
          timeoutSeconds: 5
        readinessProbe:
          httpGet:
            path: /readyz
            port: http-webhook`
          initialDelaySeconds: 10
          timeoutSeconds: 5
    extraArgs:
      - --ignore-ingress-tls-spec
    policy: sync
    sources: ["ingress", "service", "crd"]
    registry: noop
    domainFilters: ["example.com"] # replace with your domain
    ```

4. Install the Helm chart

    ```sh
    helm install external-dns-opnsense external-dns/external-dns -f external-dns-opnsense-values yaml -n external-dns
    ```

---

## 👷 Building & Testing

Build:

```sh
go build -ldflags "-s -w -X main.Version=test -X main.Gitsha=test" ./cmd/webhook
```

Run:

```sh
OPNSENSE_HOST=https://192.168.0.1 OPNSENSE_API_SECRET=<secret value> OPNSENSE_API_KEY=<key value> ./webhook
```

---

## 🤝 Gratitude and Thanks

Thank you to @crutonjohn @kashalls for their wonderful work that allowed me to create this and get it working with minimal effort.
