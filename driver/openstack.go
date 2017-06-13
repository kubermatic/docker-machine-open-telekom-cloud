package driver

import (
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"time"

	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/mcnutils"
	"github.com/docker/machine/libmachine/ssh"
	"github.com/docker/machine/libmachine/state"
)

type Driver struct {
	*drivers.BaseDriver
	AuthUrl          string
	ActiveTimeout    int
	Insecure         bool
	CaCert           string
	DomainID         string
	DomainName       string
	Username         string
	Password         string
	ProjectName      string
	ProjectID        string
	Region           string
	AvailabilityZone string
	EndpointType     string
	MachineId        string
	FlavorName       string
	FlavorId         string
	ImageName        string
	ImageId          string
	KeyPairName      string
	SubnetId         string
	UserData         []byte
	PrivateKeyFile   string
	SecurityGroups   []string
	FloatingIpPool   string
	ComputeNetwork   bool
	FloatingIpPoolId string
	IpVersion        int
	client           Client
}

const (
	defaultSSHUser        = "root"
	defaultSSHPort        = 22
	defaultActiveTimeout  = 200
	defaultFloatingIpPool = "admin_external_net"
)

func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			EnvVar: "OS_AUTH_URL",
			Name:   "otc-auth-url",
			Usage:  "Open Telekom Cloud authentication URL",
			Value:  "",
		},
		mcnflag.BoolFlag{
			EnvVar: "OS_INSECURE",
			Name:   "otc-insecure",
			Usage:  "Disable TLS credential checking.",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_CACERT",
			Name:   "otc-cacert",
			Usage:  "CA certificate bundle to verify against",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_DOMAIN_ID",
			Name:   "otc-domain-id",
			Usage:  "Open Telekom Cloud domain ID (identity v3 only)",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_DOMAIN_NAME",
			Name:   "otc-domain-name",
			Usage:  "Open Telekom Cloud domain name (identity v3 only)",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_USERNAME",
			Name:   "otc-username",
			Usage:  "Open Telekom Cloud username",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_PASSWORD",
			Name:   "otc-password",
			Usage:  "Open Telekom Cloud password",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_PROJECT_NAME",
			Name:   "otc-project-name",
			Usage:  "Open Telekom Cloud project name",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_PROJECT_ID",
			Name:   "otc-project-id",
			Usage:  "Open Telekom Cloud project id",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_REGION_NAME",
			Name:   "otc-region",
			Usage:  "Open Telekom Cloud region name",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_AVAILABILITY_ZONE",
			Name:   "otc-availability-zone",
			Usage:  "Open Telekom Cloud availability zone",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_ENDPOINT_TYPE",
			Name:   "otc-endpoint-type",
			Usage:  "Open Telekom Cloud endpoint type (adminURL, internalURL or publicURL)",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_FLAVOR_ID",
			Name:   "otc-flavor-id",
			Usage:  "Open Telekom Cloud flavor id to use for the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_FLAVOR_NAME",
			Name:   "otc-flavor-name",
			Usage:  "Open Telekom Cloud flavor name to use for the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_IMAGE_ID",
			Name:   "otc-image-id",
			Usage:  "Open Telekom Cloud image id to use for the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_IMAGE_NAME",
			Name:   "otc-image-name",
			Usage:  "Open Telekom Cloud image name to use for the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_KEYPAIR_NAME",
			Name:   "otc-keypair-name",
			Usage:  "Open Telekom Cloud keypair to use to SSH to the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_SUBNET_ID",
			Name:   "otc-subnet-id",
			Usage:  "Open Telekom Cloud network id the machine will be connected on",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_PRIVATE_KEY_FILE",
			Name:   "otc-private-key-file",
			Usage:  "Private keyfile to use for SSH (absolute path)",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_USER_DATA_FILE",
			Name:   "otc-user-data-file",
			Usage:  "File containing an Open Telekom Cloud userdata script",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_SECURITY_GROUPS",
			Name:   "otc-sec-groups",
			Usage:  "Open Telekom Cloud comma separated security groups for the machine",
			Value:  "",
		},
		mcnflag.BoolFlag{
			EnvVar: "OS_NOVA_NETWORK",
			Name:   "otc-nova-network",
			Usage:  "Use the nova networking services instead of neutron.",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_FLOATINGIP_POOL",
			Name:   "otc-floatingip-pool",
			Usage:  "Open Telekom Cloud floating IP pool to get an IP from to assign to the instance",
			Value:  defaultFloatingIpPool,
		},
		mcnflag.IntFlag{
			EnvVar: "OS_IP_VERSION",
			Name:   "otc-ip-version",
			Usage:  "Open Telekom Cloud version of IP address assigned for the machine",
			Value:  4,
		},
		mcnflag.StringFlag{
			EnvVar: "OS_SSH_USER",
			Name:   "otc-ssh-user",
			Usage:  "Open Telekom Cloud SSH user",
			Value:  defaultSSHUser,
		},
		mcnflag.IntFlag{
			EnvVar: "OS_SSH_PORT",
			Name:   "otc-ssh-port",
			Usage:  "Open Telekom Cloud SSH port",
			Value:  defaultSSHPort,
		},
		mcnflag.IntFlag{
			EnvVar: "OS_ACTIVE_TIMEOUT",
			Name:   "otc-active-timeout",
			Usage:  "Open Telekom Cloud active timeout",
			Value:  defaultActiveTimeout,
		},
	}
}

func NewDriver(hostName, storePath string) drivers.Driver {
	return NewDerivedDriver(hostName, storePath)
}

func NewDerivedDriver(hostName, storePath string) *Driver {
	return &Driver{
		client:        &GenericClient{},
		ActiveTimeout: defaultActiveTimeout,
		BaseDriver: &drivers.BaseDriver{
			SSHUser:     defaultSSHUser,
			SSHPort:     defaultSSHPort,
			MachineName: hostName,
			StorePath:   storePath,
		},
	}
}

func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()
}

func (d *Driver) SetClient(client Client) {
	d.client = client
}

// DriverName returns the name of the driver
func (d *Driver) DriverName() string {
	return "otc"
}

func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	d.AuthUrl = flags.String("otc-auth-url")
	d.ActiveTimeout = flags.Int("otc-active-timeout")
	d.Insecure = flags.Bool("otc-insecure")
	d.CaCert = flags.String("otc-cacert")
	d.DomainID = flags.String("otc-domain-id")
	d.DomainName = flags.String("otc-domain-name")
	d.Username = flags.String("otc-username")
	d.Password = flags.String("otc-password")
	d.ProjectName = flags.String("otc-project-name")
	d.ProjectID = flags.String("otc-project-id")
	d.Region = flags.String("otc-region")
	d.AvailabilityZone = flags.String("otc-availability-zone")
	d.EndpointType = flags.String("otc-endpoint-type")
	d.FlavorId = flags.String("otc-flavor-id")
	d.FlavorName = flags.String("otc-flavor-name")
	d.ImageId = flags.String("otc-image-id")
	d.ImageName = flags.String("otc-image-name")
	d.SubnetId = flags.String("otc-subnet-id")
	if flags.String("otc-sec-groups") != "" {
		d.SecurityGroups = strings.Split(flags.String("otc-sec-groups"), ",")
	}
	d.FloatingIpPool = flags.String("otc-floatingip-pool")
	d.IpVersion = flags.Int("otc-ip-version")
	d.ComputeNetwork = flags.Bool("otc-nova-network")
	d.SSHUser = flags.String("otc-ssh-user")
	d.SSHPort = flags.Int("otc-ssh-port")
	d.KeyPairName = flags.String("otc-keypair-name")
	d.PrivateKeyFile = flags.String("otc-private-key-file")

	if flags.String("otc-user-data-file") != "" {
		userData, err := ioutil.ReadFile(flags.String("otc-user-data-file"))
		if err == nil {
			d.UserData = userData
		} else {
			return err
		}
	}

	d.SetSwarmConfigFromFlags(flags)

	return d.checkConfig()
}

func (d *Driver) GetURL() (string, error) {
	if err := drivers.MustBeRunning(d); err != nil {
		return "", err
	}

	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}
	if ip == "" {
		return "", nil
	}

	return fmt.Sprintf("tcp://%s", net.JoinHostPort(ip, "2376")), nil
}

func (d *Driver) GetIP() (string, error) {
	if d.IPAddress != "" {
		return d.IPAddress, nil
	}

	log.Debug("Looking for the IP address...", map[string]string{"MachineId": d.MachineId})

	if err := d.initCompute(); err != nil {
		return "", err
	}

	addressType := Fixed
	if d.FloatingIpPool != "" {
		addressType = Floating
	}

	// Looking for the IP address in a retry loop to deal with OpenStack latency
	for retryCount := 0; retryCount < 200; retryCount++ {
		addresses, err := d.client.GetInstanceIPAddresses(d)
		if err != nil {
			return "", err
		}
		for _, a := range addresses {
			if a.AddressType == addressType && a.Version == d.IpVersion {
				return a.Address, nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	return "", fmt.Errorf("No IP found for the machine")
}

func (d *Driver) GetState() (state.State, error) {
	log.Debug("Get status for Open Telekom Cloud instance...", map[string]string{"MachineId": d.MachineId})
	if err := d.initCompute(); err != nil {
		return state.None, err
	}

	s, err := d.client.GetInstanceState(d)
	if err != nil {
		return state.None, err
	}

	log.Debug("State for Open Telekom Cloud instance", map[string]string{
		"MachineId": d.MachineId,
		"State":     s,
	})

	switch s {
	case "ACTIVE":
		return state.Running, nil
	case "PAUSED":
		return state.Paused, nil
	case "SUSPENDED":
		return state.Saved, nil
	case "SHUTOFF":
		return state.Stopped, nil
	case "BUILDING":
		return state.Starting, nil
	case "ERROR":
		return state.Error, nil
	}
	return state.None, nil
}

func (d *Driver) Create() error {
	if err := d.resolveIds(); err != nil {
		return err
	}
	if d.KeyPairName != "" {
		if err := d.loadSSHKey(); err != nil {
			return err
		}
	} else {
		d.KeyPairName = fmt.Sprintf("%s-%s", d.MachineName, mcnutils.GenerateRandomID())
		if err := d.createSSHKey(); err != nil {
			return err
		}
	}
	if err := d.createMachine(); err != nil {
		return err
	}
	if err := d.waitForInstanceActive(); err != nil {
		return err
	}
	if d.FloatingIpPool != "" {
		if err := d.assignFloatingIP(); err != nil {
			return err
		}
	}
	if err := d.lookForIPAddress(); err != nil {
		return err
	}
	return nil
}

func (d *Driver) Start() error {
	if err := d.initCompute(); err != nil {
		return err
	}

	return d.client.StartInstance(d)
}

func (d *Driver) Stop() error {
	if err := d.initCompute(); err != nil {
		return err
	}

	return d.client.StopInstance(d)
}

func (d *Driver) Restart() error {
	if err := d.initCompute(); err != nil {
		return err
	}

	return d.client.RestartInstance(d)
}

func (d *Driver) Kill() error {
	return d.Stop()
}

func (d *Driver) Remove() error {
	log.Debug("deleting instance...", map[string]string{"MachineId": d.MachineId})
	log.Info("Deleting Open Telekom Cloud instance...")
	if err := d.initCompute(); err != nil {
		return err
	}
	if err := d.client.DeleteInstance(d); err != nil {
		return err
	}
	log.Debug("deleting key pair...", map[string]string{"Name": d.KeyPairName})
	// TODO (fsoppelsa) maybe we want to check this, in case of shared keypairs, before removal
	if err := d.client.DeleteKeyPair(d, d.KeyPairName); err != nil {
		return err
	}
	return nil
}

const (
	errorMandatoryEnvOrOption     string = "%s must be specified either using the environment variable %s or the CLI option %s"
	errorMandatoryOption          string = "%s must be specified using the CLI option %s"
	errorExclusiveOptions         string = "Either %s or %s must be specified, not both"
	errorBothOptions              string = "Both %s and %s must be specified"
	errorMandatoryProjectNameOrID string = "Project id or name must be provided either using one of the environment variables OS_PROJECT_ID and OS_PROJECT_NAME or one of the CLI options --otc-project-id and --otc-project-name"
	errorWrongEndpointType        string = "Endpoint type must be 'publicURL', 'adminURL' or 'internalURL'"
	errorUnknownFlavorName        string = "Unable to find flavor named %s"
	errorUnknownImageName         string = "Unable to find image named %s"
	errorUnknownNetworkName       string = "Unable to find network named %s"
	errorUnknownProjectName       string = "Unable to find project named %s"
)

func (d *Driver) checkConfig() error {
	if d.AuthUrl == "" {
		return fmt.Errorf(errorMandatoryEnvOrOption, "Authentication URL", "OS_AUTH_URL", "--otc-auth-url")
	}
	if d.Username == "" {
		return fmt.Errorf(errorMandatoryEnvOrOption, "Username", "OS_USERNAME", "--otc-username")
	}
	if d.Password == "" {
		return fmt.Errorf(errorMandatoryEnvOrOption, "Password", "OS_PASSWORD", "--otc-password")
	}
	if d.ProjectName == "" && d.ProjectID == "" {
		return fmt.Errorf(errorMandatoryProjectNameOrID)
	}

	if d.FlavorName == "" && d.FlavorId == "" {
		return fmt.Errorf(errorMandatoryOption, "Flavor name or Flavor id", "--otc-flavor-name or --otc-flavor-id")
	}
	if d.FlavorName != "" && d.FlavorId != "" {
		return fmt.Errorf(errorExclusiveOptions, "Flavor name", "Flavor id")
	}

	if d.ImageName == "" && d.ImageId == "" {
		return fmt.Errorf(errorMandatoryOption, "Image name or Image id", "--otc-image-name or --otc-image-id")
	}
	if d.ImageName != "" && d.ImageId != "" {
		return fmt.Errorf(errorExclusiveOptions, "Image name", "Image id")
	}

	if d.SubnetId == "" {
		return fmt.Errorf(errorMandatoryOption, "Subnet id", "--otc-subnet-id")
	}
	if d.EndpointType != "" && (d.EndpointType != "publicURL" && d.EndpointType != "adminURL" && d.EndpointType != "internalURL") {
		return fmt.Errorf(errorWrongEndpointType)
	}
	if (d.KeyPairName != "" && d.PrivateKeyFile == "") || (d.KeyPairName == "" && d.PrivateKeyFile != "") {
		return fmt.Errorf(errorBothOptions, "KeyPairName", "PrivateKeyFile")
	}
	return nil
}

func (d *Driver) resolveIds() error {
	if d.FlavorName != "" {
		if err := d.initCompute(); err != nil {
			return err
		}
		flavorID, err := d.client.GetFlavorID(d)

		if err != nil {
			return err
		}

		if flavorID == "" {
			return fmt.Errorf(errorUnknownFlavorName, d.FlavorName)
		}

		d.FlavorId = flavorID
		log.Debug("Found flavor id using its name", map[string]string{
			"Name": d.FlavorName,
			"ID":   d.FlavorId,
		})
	}

	if d.ImageName != "" {
		if err := d.initCompute(); err != nil {
			return err
		}
		imageID, err := d.client.GetImageID(d)

		if err != nil {
			return err
		}

		if imageID == "" {
			return fmt.Errorf(errorUnknownImageName, d.ImageName)
		}

		d.ImageId = imageID
		log.Debug("Found image id using its name", map[string]string{
			"Name": d.ImageName,
			"ID":   d.ImageId,
		})
	}

	if d.FloatingIpPool != "" && !d.ComputeNetwork {
		if err := d.initNetwork(); err != nil {
			return err
		}
		f, err := d.client.GetFloatingIPPoolID(d)

		if err != nil {
			return err
		}

		if f == "" {
			return fmt.Errorf(errorUnknownNetworkName, d.FloatingIpPool)
		}

		d.FloatingIpPoolId = f
		log.Debug("Found floating IP pool id using its name", map[string]string{
			"Name": d.FloatingIpPool,
			"ID":   d.FloatingIpPoolId,
		})
	}

	if d.ProjectName != "" && d.ProjectID == "" {
		if err := d.initIdentity(); err != nil {
			return err
		}
		projectID, err := d.client.GetProjectID(d)

		if err != nil {
			return err
		}

		if projectID == "" {
			return fmt.Errorf(errorUnknownProjectName, d.ProjectName)
		}

		d.ProjectID = projectID
		log.Debug("Found project id using its name", map[string]string{
			"Name": d.ProjectName,
			"ID":   d.ProjectID,
		})
	}

	return nil
}

func (d *Driver) initCompute() error {
	if err := d.client.Authenticate(d); err != nil {
		return err
	}
	if err := d.client.InitComputeClient(d); err != nil {
		return err
	}
	return nil
}

func (d *Driver) initIdentity() error {
	if err := d.client.Authenticate(d); err != nil {
		return err
	}
	if err := d.client.InitIdentityClient(d); err != nil {
		return err
	}
	return nil
}

func (d *Driver) initNetwork() error {
	if err := d.client.Authenticate(d); err != nil {
		return err
	}
	if err := d.client.InitNetworkClient(d); err != nil {
		return err
	}
	return nil
}

func (d *Driver) loadSSHKey() error {
	log.Debug("Loading Key Pair", d.KeyPairName)
	if err := d.initCompute(); err != nil {
		return err
	}
	log.Debug("Loading Private Key from", d.PrivateKeyFile)
	privateKey, err := ioutil.ReadFile(d.PrivateKeyFile)
	if err != nil {
		return err
	}
	publicKey, err := d.client.GetPublicKey(d.KeyPairName)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(d.privateSSHKeyPath(), privateKey, 0600); err != nil {
		return err
	}
	if err := ioutil.WriteFile(d.publicSSHKeyPath(), publicKey, 0600); err != nil {
		return err
	}

	return nil
}

func (d *Driver) createSSHKey() error {
	sanitizeKeyPairName(&d.KeyPairName)
	log.Debug("Creating Key Pair...", map[string]string{"Name": d.KeyPairName})
	if err := ssh.GenerateSSHKey(d.GetSSHKeyPath()); err != nil {
		return err
	}
	publicKey, err := ioutil.ReadFile(d.publicSSHKeyPath())
	if err != nil {
		return err
	}

	if err := d.initCompute(); err != nil {
		return err
	}
	if err := d.client.CreateKeyPair(d, d.KeyPairName, string(publicKey)); err != nil {
		return err
	}
	return nil
}

func (d *Driver) createMachine() error {
	log.Debug("Creating Open Telekom Cloud instance...", map[string]string{
		"FlavorId": d.FlavorId,
		"ImageId":  d.ImageId,
	})

	if err := d.initCompute(); err != nil {
		return err
	}
	instanceID, err := d.client.CreateInstance(d)
	if err != nil {
		return err
	}
	d.MachineId = instanceID
	return nil
}

func (d *Driver) assignFloatingIP() error {
	var err error

	if d.ComputeNetwork {
		err = d.initCompute()
	} else {
		err = d.initNetwork()
	}

	if err != nil {
		return err
	}

	ips, err := d.client.GetFloatingIPs(d)
	if err != nil {
		return err
	}

	var floatingIP *FloatingIP

	log.Debugf("Looking for an available floating IP", map[string]string{
		"MachineId": d.MachineId,
		"Pool":      d.FloatingIpPool,
	})

	for _, ip := range ips {
		if ip.PortId == "" {
			log.Debug("Available floating IP found", map[string]string{
				"MachineId": d.MachineId,
				"IP":        ip.Ip,
			})
			floatingIP = &ip
			break
		}
	}

	if floatingIP == nil {
		floatingIP = &FloatingIP{}
		log.Debug("No available floating IP found. Allocating a new one...", map[string]string{"MachineId": d.MachineId})
	} else {
		log.Debug("Assigning floating IP to the instance", map[string]string{"MachineId": d.MachineId})
	}

	if err := d.client.AssignFloatingIP(d, floatingIP); err != nil {
		return err
	}
	d.IPAddress = floatingIP.Ip
	return nil
}

func (d *Driver) waitForInstanceActive() error {
	log.Debug("Waiting for the Open Telekom Cloud instance to be ACTIVE...", map[string]string{"MachineId": d.MachineId})
	if err := d.client.WaitForInstanceStatus(d, "ACTIVE"); err != nil {
		return err
	}
	return nil
}

func (d *Driver) lookForIPAddress() error {
	ip, err := d.GetIP()
	if err != nil {
		return err
	}
	d.IPAddress = ip
	log.Debug("IP address found", map[string]string{
		"IP":        ip,
		"MachineId": d.MachineId,
	})
	return nil
}

func (d *Driver) privateSSHKeyPath() string {
	return d.GetSSHKeyPath()
}

func (d *Driver) publicSSHKeyPath() string {
	return d.GetSSHKeyPath() + ".pub"
}

func sanitizeKeyPairName(s *string) {
	*s = strings.Replace(*s, ".", "_", -1)
}
