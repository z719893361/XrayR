package newV2board

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bitly/go-simplejson"
	"github.com/go-resty/resty/v2"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/XrayR-project/XrayR/api"
)

// APIClient create an api client to the panel.
type APIClient struct {
	client        *resty.Client
	APIHost       string
	NodeID        int
	Key           string
	NodeType      string
	EnableVless   bool
	VlessFlow     string
	SpeedLimit    float64
	DeviceLimit   int
	LocalRuleList []api.DetectRule
	resp          atomic.Value
	eTags         map[string]string
}

// New create an api instance
func New(apiConfig *api.Config) *APIClient {
	client := resty.New()
	client.SetRetryCount(3)
	if apiConfig.Timeout > 0 {
		client.SetTimeout(time.Duration(apiConfig.Timeout) * time.Second)
	} else {
		client.SetTimeout(5 * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		if v, ok := err.(*resty.ResponseError); ok {
			// v.Response contains the last response from the server
			// v.Err contains the original error
			log.Print(v.Err)
		}
	})
	client.SetBaseURL(apiConfig.APIHost)

	var nodeType string

	if apiConfig.NodeType == "V2ray" && apiConfig.EnableVless {
		nodeType = "vless"
	} else {
		nodeType = "vmess"
	}
	// Create Key for each requests
	client.SetQueryParams(map[string]string{
		"node_id":   strconv.Itoa(apiConfig.NodeID),
		"node_type": nodeType,
		"token":     apiConfig.Key,
	})
	// Read local rule list
	localRuleList := readLocalRuleList(apiConfig.RuleListPath)
	apiClient := &APIClient{
		client:        client,
		NodeID:        apiConfig.NodeID,
		Key:           apiConfig.Key,
		APIHost:       apiConfig.APIHost,
		NodeType:      apiConfig.NodeType,
		EnableVless:   apiConfig.EnableVless,
		VlessFlow:     apiConfig.VlessFlow,
		SpeedLimit:    apiConfig.SpeedLimit,
		DeviceLimit:   apiConfig.DeviceLimit,
		LocalRuleList: localRuleList,
		eTags:         make(map[string]string),
	}
	return apiClient
}

// readLocalRuleList reads the local rule list file
func readLocalRuleList(path string) (LocalRuleList []api.DetectRule) {
	LocalRuleList = make([]api.DetectRule, 0)

	if path != "" {
		// open the file
		file, err := os.Open(path)
		defer file.Close()
		// handle errors while opening
		if err != nil {
			log.Printf("Error when opening file: %s", err)
			return LocalRuleList
		}

		fileScanner := bufio.NewScanner(file)

		// read line by line
		for fileScanner.Scan() {
			LocalRuleList = append(LocalRuleList, api.DetectRule{
				ID:      -1,
				Pattern: regexp.MustCompile(fileScanner.Text()),
			})
		}
		// handle first encountered error while reading
		if err := fileScanner.Err(); err != nil {
			log.Fatalf("Error while reading file: %s", err)
			return
		}
	}

	return LocalRuleList
}

// Describe return a description of the client
func (apiClient *APIClient) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: apiClient.APIHost, NodeID: apiClient.NodeID, Key: apiClient.Key, NodeType: apiClient.NodeType}
}

// Debug set the client debug for client
func (apiClient *APIClient) Debug() {
	apiClient.client.SetDebug(true)
}

func (apiClient *APIClient) assembleURL(path string) string {
	return apiClient.APIHost + path
}

func (apiClient *APIClient) parseResponse(res *resty.Response, path string, err error) (*simplejson.Json, error) {
	if err != nil {
		return nil, fmt.Errorf("request %s failed: %v", apiClient.assembleURL(path), err)
	}

	if res.StatusCode() > 399 {
		return nil, fmt.Errorf("request %s failed: %s, %v", apiClient.assembleURL(path), res.String(), err)
	}

	rtn, err := simplejson.NewJson(res.Body())
	if err != nil {
		return nil, fmt.Errorf("ret %s invalid", res.String())
	}

	return rtn, nil
}

// GetNodeInfo will pull NodeInfo Config from panel
func (apiClient *APIClient) GetNodeInfo() (nodeInfo *api.NodeInfo, err error) {
	server := new(serverConfig)
	path := "/api/v1/server/UniProxy/config"

	res, err := apiClient.client.R().
		SetHeader("If-None-Match", apiClient.eTags["node"]).
		ForceContentType("application/json").
		Get(path)

	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, errors.New(api.NodeNotModified)
	}
	// update etag
	if res.Header().Get("Etag") != "" && res.Header().Get("Etag") != apiClient.eTags["node"] {
		apiClient.eTags["node"] = res.Header().Get("Etag")
	}

	nodeInfoResp, err := apiClient.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}
	b, _ := nodeInfoResp.Encode()
	json.Unmarshal(b, server)

	if server.ServerPort == 0 {
		return nil, errors.New("server port must > 0")
	}

	apiClient.resp.Store(server)

	switch apiClient.NodeType {
	case "V2ray":
		nodeInfo, err = apiClient.parseV2rayNodeResponse(server)
	case "Trojan":
		nodeInfo, err = apiClient.parseTrojanNodeResponse(server)
	case "Shadowsocks":
		nodeInfo, err = apiClient.parseSSNodeResponse(server)
	default:
		return nil, fmt.Errorf("unsupported node type: %s", apiClient.NodeType)
	}

	if err != nil {
		return nil, fmt.Errorf("parse node info failed: %s, \nError: %v", res.String(), err)
	}

	return nodeInfo, nil
}

// GetUserList will pull user form panel
func (apiClient *APIClient) GetUserList() (UserList *[]api.UserInfo, err error) {
	path := "/api/v1/server/UniProxy/user"
	switch apiClient.NodeType {
	case "V2ray", "Trojan", "Shadowsocks":
		break
	default:
		return nil, fmt.Errorf("unsupported node type: %s", apiClient.NodeType)
	}
	res, err := apiClient.client.R().
		SetHeader("If-None-Match", apiClient.eTags["users"]).
		ForceContentType("application/json").
		Get(path)
	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, errors.New(api.UserNotModified)
	}
	// update etag
	if res.Header().Get("Etag") != "" && res.Header().Get("Etag") != apiClient.eTags["users"] {
		apiClient.eTags["users"] = res.Header().Get("Etag")
	}

	usersResp, err := apiClient.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}
	b, _ := usersResp.Get("users").Encode()
	var users []*User
	err = json.Unmarshal(b, &users)
	if err != nil {
		return nil, err
	}
	userNodes := make([]api.UserInfo, len(users))
	for i := 0; i < len(users); i++ {
		user := api.UserInfo{
			UID:  users[i].Id,
			UUID: users[i].Uuid,
		}
		if apiClient.SpeedLimit > 0 {
			user.SpeedLimit = uint64(apiClient.SpeedLimit * 1000000 / 8)
		} else {
			user.SpeedLimit = uint64(users[i].SpeedLimit * 1000000 / 8)
		}
		if apiClient.DeviceLimit > 0 {
			user.DeviceLimit = apiClient.DeviceLimit
		} else {
			user.DeviceLimit = users[i].DeviceLimit
		}
		userNodes[i] = user
	}
	return &userNodes, nil
}

// ReportUserTraffic reports the user traffic
func (apiClient *APIClient) ReportUserTraffic(userTraffic *[]api.UserTraffic) error {
	path := "/api/v1/server/UniProxy/push"

	// json structure: {uid1: [u, d], uid2: [u, d], uid1: [u, d], uid3: [u, d]}
	data := make(map[int][]int64, len(*userTraffic))
	for _, traffic := range *userTraffic {
		data[traffic.UID] = []int64{traffic.Upload, traffic.Download}
	}

	res, err := apiClient.client.R().SetBody(data).ForceContentType("application/json").Post(path)
	_, err = apiClient.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}

// GetNodeRule implements the API interface
func (apiClient *APIClient) GetNodeRule() (*[]api.DetectRule, error) {
	routes := apiClient.resp.Load().(*serverConfig).Routes

	ruleList := apiClient.LocalRuleList

	for i := range routes {
		if routes[i].Action == "block" {
			ruleList = append(ruleList, api.DetectRule{
				ID:      i,
				Pattern: regexp.MustCompile(strings.Join(routes[i].Match, "|")),
			})
		}
	}

	return &ruleList, nil
}

// ReportNodeStatus implements the API interface
func (apiClient *APIClient) ReportNodeStatus(nodeStatus *api.NodeStatus) (err error) {
	return nil
}

// ReportNodeOnlineUsers implements the API interface
func (apiClient *APIClient) ReportNodeOnlineUsers(onlineUserList *[]api.OnlineUser) error {
	return nil
}

// ReportIllegal implements the API interface
func (apiClient *APIClient) ReportIllegal(detectResultList *[]api.DetectResult) error {
	return nil
}

// parseTrojanNodeResponse parse the response for the given nodeInfo format
func (apiClient *APIClient) parseTrojanNodeResponse(s *serverConfig) (*api.NodeInfo, error) {
	// Create GeneralNodeInfo
	nodeInfo := &api.NodeInfo{
		NodeType:          apiClient.NodeType,
		NodeID:            apiClient.NodeID,
		Port:              uint32(s.ServerPort),
		TransportProtocol: "tcp",
		EnableTLS:         true,
		Host:              s.Host,
		ServiceName:       s.ServerName,
		NameServerConfig:  s.parseDNSConfig(),
	}
	return nodeInfo, nil
}

// parseSSNodeResponse parse the response for the given nodeInfo format
func (apiClient *APIClient) parseSSNodeResponse(s *serverConfig) (*api.NodeInfo, error) {
	var header json.RawMessage

	if s.Obfs == "http" {
		path := "/"
		if p := s.ObfsSettings.Path; p != "" {
			if strings.HasPrefix(p, "/") {
				path = p
			} else {
				path += p
			}
		}
		h := simplejson.New()
		h.Set("type", "http")
		h.SetPath([]string{"request", "path"}, path)
		header, _ = h.Encode()
	}
	// Create GeneralNodeInfo
	return &api.NodeInfo{
		NodeType:          apiClient.NodeType,
		NodeID:            apiClient.NodeID,
		Port:              uint32(s.ServerPort),
		TransportProtocol: "tcp",
		CypherMethod:      s.Cipher,
		ServerKey:         s.ServerKey, // shadowsocks2022 share key
		NameServerConfig:  s.parseDNSConfig(),
		Header:            header,
	}, nil
}

// parseV2rayNodeResponse parse the response for the given nodeInfo format
func (apiClient *APIClient) parseV2rayNodeResponse(s *serverConfig) (*api.NodeInfo, error) {
	var (
		host          string
		header        json.RawMessage
		enableTLS     bool
		enableREALITY bool
		dest          string
		xVer          uint64
	)

	if s.VlessTlsSettings.Dest != "" {
		dest = s.VlessTlsSettings.Dest
	} else {
		dest = s.VlessTlsSettings.Sni
	}
	if s.VlessTlsSettings.xVer != 0 {
		xVer = s.VlessTlsSettings.xVer
	} else {
		xVer = 0
	}

	realityConfig := api.REALITYConfig{
		Dest:             dest + ":" + s.VlessTlsSettings.ServerPort,
		ProxyProtocolVer: xVer,
		ServerNames:      []string{s.VlessTlsSettings.Sni},
		PrivateKey:       s.VlessTlsSettings.PrivateKey,
		ShortIds:         []string{s.VlessTlsSettings.ShortId},
	}

	if apiClient.EnableVless {
		s.NetworkSettings = s.VlessNetworkSettings
	}

	switch s.Network {
	case "ws":
		if s.NetworkSettings.Headers != nil {
			if httpHeader, err := s.NetworkSettings.Headers.MarshalJSON(); err != nil {
				return nil, err
			} else {
				b, _ := simplejson.NewJson(httpHeader)
				host = b.Get("Host").MustString()
			}
		}
	case "tcp":
		if s.NetworkSettings.Header != nil {
			if httpHeader, err := s.NetworkSettings.Header.MarshalJSON(); err != nil {
				return nil, err
			} else {
				header = httpHeader
			}
		}
	}

	switch s.Tls {
	case 0:
		enableTLS = false
		enableREALITY = false
	case 1:
		enableTLS = true
		enableREALITY = false
	case 2:
		enableTLS = true
		enableREALITY = true
	}

	// Create GeneralNodeInfo
	return &api.NodeInfo{
		NodeType:          apiClient.NodeType,
		NodeID:            apiClient.NodeID,
		Port:              uint32(s.ServerPort),
		AlterID:           0,
		TransportProtocol: s.Network,
		EnableTLS:         enableTLS,
		Path:              s.NetworkSettings.Path,
		Host:              host,
		EnableVless:       apiClient.EnableVless,
		VlessFlow:         s.VlessFlow,
		ServiceName:       s.NetworkSettings.ServiceName,
		Header:            header,
		EnableREALITY:     enableREALITY,
		REALITYConfig:     &realityConfig,
		NameServerConfig:  s.parseDNSConfig(),
	}, nil
}

func (s *serverConfig) parseDNSConfig() (nameServerList []*conf.NameServerConfig) {
	for i := range s.Routes {
		if s.Routes[i].Action == "dns" {
			nameServerList = append(nameServerList, &conf.NameServerConfig{
				Address: &conf.Address{Address: net.ParseAddress(s.Routes[i].ActionValue)},
				Domains: s.Routes[i].Match,
			})
		}
	}

	return
}
