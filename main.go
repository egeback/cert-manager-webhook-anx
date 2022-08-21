package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog"

	corev1 "k8s.io/api/core/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/egeback/anxdns-go/anxdns"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/cmd"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our anx DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&anxDNSProviderSolver{},
	)
}

// anxDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/jetstack/cert-manager/pkg/acme/webhook.Solver`
// interface.
type anxDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	client *kubernetes.Clientset
}

// anxDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type anxDNSProviderConfig struct {
	BaseURL         string                   `json:"baseURL"`
	APIKeySecretRef corev1.SecretKeySelector `json:"apiKeySecretRef"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *anxDNSProviderSolver) Name() string {
	return "anxdns"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *anxDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig((*extapi.JSON)(ch.Config))

	if err != nil {
		return err
	}

	// Get Kubernetes secrets
	apiKey, err := c.getSecretValue(cfg.APIKeySecretRef, ch.ResourceNamespace)
	if err != nil {
		return err
	}

	// Create client
	domain := util.UnFqdn(ch.ResolvedZone)

	// fmt.Println("Domain: " + domain)
	// fmt.Println("ApiUrl: " + cfg.BaseURL)
	// fmt.Println("Label: " + ch.Key)
	// fmt.Println("FQDN:" + ch.ResolvedFQDN)
	client := anxdns.NewClient(domain, string(apiKey))
	if len(cfg.BaseURL) > 0 {
		client.BaseUrl = cfg.BaseURL
	}

	// fmt.Println("Start add")
	error := client.AddTxtRecord(ch.ResolvedFQDN, ch.Key, 120)
	if error != nil {
		fmt.Println(error)
		klog.Fatal(error)
	}
	// fmt.Println("End add")

	return error
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *anxDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	// fmt.Println("Cleanup")
	cfg, err := loadConfig((*extapi.JSON)(ch.Config))

	if err != nil {
		return err
	}

	// Get Kubernetes secrets
	apiKey, err := c.getSecretValue(cfg.APIKeySecretRef, ch.ResourceNamespace)
	if err != nil {
		return err
	}

	// Create client
	domain := util.UnFqdn(ch.ResolvedZone)
	client := anxdns.NewClient(domain, string(apiKey))

	//klog.Fatal(error)

	// fmt.Println("Start delete")
	error := client.DeleteRecordsByTxt(ch.ResolvedFQDN, ch.Key)

	if error != nil {
		if strings.Contains(fmt.Sprint(error), "0 records") {
			error = nil
		} else {
			fmt.Println(error)
			klog.Fatal(error)
		}
	}
	// fmt.Println("Stop delete")

	return error
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *anxDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl
	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (anxDNSProviderConfig, error) {
	cfg := anxDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}
	return cfg, nil
}

// getSecretValue returns the kubernetes secrets
func (c *anxDNSProviderSolver) getSecretValue(selector corev1.SecretKeySelector, ns string) ([]byte, error) {
	secret, err := c.client.CoreV1().Secrets(ns).Get(context.Background(), selector.Name, metaV1.GetOptions{})
	if err != nil {
		return nil, err
	}

	if value, ok := secret.Data[selector.Key]; ok {
		return value, nil
	}
	return nil, err
}
