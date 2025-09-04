package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/go-acme/lego/v4/providers/dns/httpnet"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&httpnetDNSProviderSolver{},
	)
}

// httpnetDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type httpnetDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.

	client *kubernetes.Clientset
}

// httpnetDNSProviderConfig is a structure that is used to decode into when
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
type httpnetDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	SecretName string `json:"secret"`
	KeyName    string `json:"key"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *httpnetDNSProviderSolver) Name() string {
	return "httpnet"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *httpnetDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	token, err := getToken(c.client, ch)
	if err != nil {
		return err
	}

	provider, err := getProvider(token)

	if err != nil {
		return fmt.Errorf("failed to create http.net provider: %w", err)
	}

	// Normalize trailing dots for provider API expectations
	zone := strings.TrimSuffix(ch.ResolvedZone, ".")
	fqdn := strings.TrimSuffix(ch.DNSName, ".")

	klog.Infof("Creating DNS record: %s with key '%s'", ch.ResolvedFQDN, ch.Key)

	legoError := provider.Present(fqdn, ch.Key, zone)

	if legoError != nil {
		if strings.Contains(legoError.Error(), "is a duplicate") {
			klog.Infof("DNS record already created: %s", ch.ResolvedFQDN)
			return nil
		}

		klog.Errorf("Error creating DNS record: %s", legoError)
	} else {
		klog.Infof("Created DNS record: %s", ch.ResolvedFQDN)
	}

	return legoError
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *httpnetDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	token, err := getToken(c.client, ch)
	if err != nil {
		return err
	}

	provider, err := getProvider(token)

	if err != nil {
		return fmt.Errorf("failed to create http.net provider: %w", err)
	}

	// Normalize trailing dots for provider API expectations
	zone := strings.TrimSuffix(ch.ResolvedZone, ".")
	fqdn := strings.TrimSuffix(ch.DNSName, ".")

	klog.Infof("Deleting DNS record: %s with key '%s'", ch.ResolvedFQDN, ch.Key)

	legoError := provider.CleanUp(fqdn, ch.Key, zone)

	if legoError != nil {
		if strings.Contains(legoError.Error(), "does not exist") {
			klog.Infof("DNS record already deleted: %s", ch.ResolvedFQDN)
			return nil
		}

		klog.Warningf("Error deleting DNS record: %s", legoError)
	} else {
		klog.Infof("Deleted DNS record: %s", ch.ResolvedFQDN)
	}
	return legoError
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
func (c *httpnetDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {

	k8sclient, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = k8sclient

	return nil
}

func getProvider(token string) (*httpnet.DNSProvider, error) {
	config := httpnet.NewDefaultConfig()
	config.APIKey = token

	provider, err := httpnet.NewDNSProviderConfig(config)

	if err != nil {
		return nil, fmt.Errorf("failed to create http.net provider: %w", err)
	}

	return provider, nil
}

func getToken(k8sclient *kubernetes.Clientset, challenge *v1alpha1.ChallengeRequest) (string, error) {
	cfg, err := loadConfig(challenge.Config)
	if err != nil {
		return "", err
	}

	namespace := os.Getenv("POD_NAMESPACE")

	sec, err := k8sclient.CoreV1().Secrets(namespace).Get(context.TODO(), cfg.SecretName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get secret %s/%s: %w", namespace, cfg.SecretName, err)
	}

	data, ok := sec.Data[cfg.KeyName]
	if !ok {
		return "", fmt.Errorf("secret %s/%s does not contain key %q", namespace, cfg.SecretName, cfg.KeyName)
	}

	return string(data), nil

}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (httpnetDNSProviderConfig, error) {
	cfg := httpnetDNSProviderConfig{}

	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}
