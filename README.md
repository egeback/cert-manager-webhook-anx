# cert-manager webhook for anx.se
cert-manager ACME DNS01 webhook provider for anx.se
## Prequesites
The following components needs to be already installed on a Kubernetes cluster:
 * Kubernetes (>= v1.11.0) [](https://kubernetes.io/)
 * cert-manager (>= v0.14.0) [](https://cert-manager.io/docs/installation/kubernetes/)
 * helm (>= v3.0.0) [](https://helm.sh/docs/intro/install/)

Your domain needs to have Dynamic DNS support and an api key from https://dyn.anx.se.

## Installation
 1. Create a Kubernetes secret which will hold your joker DynDNS authentication credentials (base64 representation):
 
```yaml
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: anxdns-secret
  namespace: <namespace where cert-manager provider resides>
data:
  apiKey: <api_key>
EOF
```
 
 2. Grant permission to get the secret to `cert-manager-webhook-anxdns` service account:

 ```yaml
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cert-manager-webhook-anxdns:secret-reader
  namespace: <namespace where cert-manager provider resides>
rules:
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["anxdns-secret"]
  verbs: ["get", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cert-manager-webhook-anxdns:secret-reader
  namespace: <namespace where cert-manager provider resides>
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: cert-manager-webhook-anxdns:secret-reader
subjects:
- apiGroup: ""
  kind: ServiceAccount
  name: cert-manager-webhook-anxdns
EOF
```

3. Clone the github repository:
 
```console
git clone https://github.com/egeback/cert-manager-webhook-anx.git
```

 4. Install the Helm chart with:

```console
helm upgrade --install cert-manager-webhook-anxdns --namespace cert-manager deploy/anxdns-webhook
```

 5. Create a certificate issuer with the letsencrypt staging ca for testing purposes (you must insert your e-mail address):

```yaml
cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-staging-dns01
spec:
  acme:
    # Change to your letsencrypt email
    email: <your email>
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: letsencrypt-staging-account-key
    solvers:
    - dns01:
        webhook:
          groupName: acme.anx.se
          solverName: anxdns
          config:
            baseURL: https://dyn.anx.se/api/dns/
            apiKeySecretRef:
		name: anxdns-secret
		key: apiKey
EOF
```

 6. Issue a test certificate (replace the test urls in here):

```yaml
cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1alpha2
kind: Certificate
metadata:
  name: example-tls
spec:
  secretName: example-com-tls
  commonName: example.com
  dnsNames:
  - example.com
  - "*.example.com"
  issuerRef:
    name: letsencrypt-staging-dns01
    kind: ClusterIssuer
EOF
```
