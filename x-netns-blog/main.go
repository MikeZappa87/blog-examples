// Copyright 2017 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This is a sample chained plugin that supports multiple CNI versions. It
// parses prevResult according to the cniVersion
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// PluginConf is whatever you expect your configuration json to be. This is whatever
// is passed in on stdin. Your plugin may wish to expose its functionality via
// runtime args, see CONVENTIONS.md in the CNI spec.
type PluginConf struct {
	// This embeds the standard NetConf structure which allows your plugin
	// to more easily parse standard fields like Name, Type, CNIVersion,
	// and PrevResult.
	types.NetConf

	RuntimeConfig *struct {
		SampleConfig map[string]interface{} `json:"sample"`
	} `json:"runtimeConfig"`

	NetId string `json:"netid"`
}

// parseConfig parses the supplied configuration (and prevResult) from stdin.
func parseConfig(stdin []byte) (*PluginConf, error) {
	conf := PluginConf{}

	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse network configuration: %v", err)
	}

	// Parse previous result. This will parse, validate, and place the
	// previous result object into conf.PrevResult. If you need to modify
	// or inspect the PrevResult you will need to convert it to a concrete
	// versioned Result struct.
	if err := version.ParsePrevResult(&conf.NetConf); err != nil {
		return nil, fmt.Errorf("could not parse prevResult: %v", err)
	}
	// End previous result parsing

	// Do any validation here
	if conf.NetId == "" { // Need to check if this is a valid linux interface name
		return nil, fmt.Errorf("id must be specified")
	}

	return &conf, nil
}

func IsDir(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false
	}

	if fileInfo.IsDir() {
		return true
	} else {
		return false
	}
}

func Sanitize(name string) {

	path := fmt.Sprintf("/run/netns/%s/", name)

	if IsDir(path) {
		os.RemoveAll(path)
	}
}

// cmdAdd is called for ADD requests
func cmdAdd(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	Sanitize(conf.NetId)

	//We need to grab the file descriptor for the root netns
	curnetns, err := netns.Get()

	if err != nil {
		return err
	}

	//FYI this creates and THEN ENTERS the netns
	hnd, err := netns.NewNamed(conf.NetId)

	if err != nil {
		return err
	}

	defer hnd.Close()

	veth := netlink.Veth{}
	veth.Name = "veth0"
	veth.PeerName = fmt.Sprintf("v%s", conf.NetId)
	veth.PeerNamespace = netlink.NsFd(curnetns)

	err = netlink.LinkAdd(&veth)

	if err != nil {
		return err
	}

	addr, err := netlink.ParseAddr("1.2.3.4/24")

	if err != nil {
		return err
	}

	err = netlink.AddrAdd(&veth, addr)

	if err != nil {
		return err
	}

	err = netlink.LinkSetUp(&veth)

	if err != nil {
		return err
	}

	lo, _ := netlink.LinkByName("lo")

	err = netlink.LinkSetUp(lo)

	if err != nil {
		return err
	}

	_, defaultDst, _ := net.ParseCIDR("0.0.0.0/0")
	route := netlink.Route{Dst: defaultDst, LinkIndex: veth.Index}

	err = netlink.RouteAdd(&route)

	if err != nil {
		return err
	}

	//move back into the root netns
	err = netns.Set(netns.NsHandle(curnetns))

	if err != nil {
		return err
	}

	peer, err := netlink.LinkByName(veth.PeerName)

	if err != nil {
		return err
	}

	err = netlink.LinkSetUp(peer)

	if err != nil {
		return err
	}

	result := &current.Result{CNIVersion: current.ImplementedSpecVersion}

	result.Interfaces = append(result.Interfaces, &current.Interface{
		Name:    veth.PeerName,
		Mac:     veth.HardwareAddr.String(),
		Sandbox: conf.NetId,
	})

	result.IPs = append(result.IPs, &current.IPConfig{
		Address:   *addr.IPNet,
		Interface: current.Int(0),
	})

	// Pass through the result for the next plugin
	return types.PrintResult(result, conf.CNIVersion)
}

// cmdDel is called for DELETE requests
func cmdDel(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	Sanitize(conf.NetId)

	netns.DeleteNamed(conf.NetId)

	return nil
}

func main() {
	// replace TODO with your plugin name
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, "cni-route")
}

func GetVethLinks() ([]netlink.Veth, error) {
	links, err := netlink.LinkList()

	if err != nil {
		return nil, err
	}

	var veths []netlink.Veth
	for _, v := range links {
		if veth, ok := v.(*netlink.Veth); ok {
			veths = append(veths, *veth)
		}
	}

	return veths, nil
}

func cmdCheck(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	_, err = netns.GetFromName(conf.NetId)

	if err != nil {
		return err
	}

	return nil
}
