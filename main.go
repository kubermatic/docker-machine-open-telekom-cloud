package main

import (
	"github.com/docker/machine/libmachine/drivers/plugin"
	"github.com/kubermatic/docker-machine-openstack/driver"
)

func main() {
	plugin.RegisterDriver(driver.NewDriver("default", "path"))
}
