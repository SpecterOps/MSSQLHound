// Package bloodhound provides BloodHound OpenGraph JSON output generation.
package bloodhound

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// Node represents a BloodHound graph node
type Node struct {
	ID         string                 `json:"id"`
	Kinds      []string               `json:"kinds"`
	Properties map[string]interface{} `json:"properties"`
	Icon       *Icon                  `json:"icon,omitempty"`
}

// Edge represents a BloodHound graph edge
type Edge struct {
	Start      EdgeEndpoint           `json:"start"`
	End        EdgeEndpoint           `json:"end"`
	Kind       string                 `json:"kind"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// EdgeEndpoint represents the start or end of an edge
type EdgeEndpoint struct {
	Value string `json:"value"`
}

// Icon represents a node icon
type Icon struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Color string `json:"color"`
}

// StreamingWriter handles streaming JSON output for BloodHound format
type StreamingWriter struct {
	file      *os.File
	encoder   *json.Encoder
	mu        sync.Mutex
	nodeCount int
	edgeCount int
	firstNode bool
	firstEdge bool
	inEdges   bool
	filePath  string
}

// NewStreamingWriter creates a new streaming BloodHound JSON writer
func NewStreamingWriter(filePath string) (*StreamingWriter, error) {
	// Ensure directory exists
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	file, err := os.Create(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create file: %w", err)
	}

	w := &StreamingWriter{
		file:      file,
		firstNode: true,
		firstEdge: true,
		filePath:  filePath,
	}

	// Write header
	if err := w.writeHeader(); err != nil {
		file.Close()
		return nil, err
	}

	return w, nil
}

// writeHeader writes the initial JSON structure
func (w *StreamingWriter) writeHeader() error {
	header := `{
  "$schema": "https://raw.githubusercontent.com/MichaelGrafnetter/EntraAuthPolicyHound/refs/heads/main/bloodhound-opengraph.schema.json",
  "metadata": {
    "source_kind": "MSSQL_Base"
  },
  "graph": {
    "nodes": [
`
	_, err := w.file.WriteString(header)
	return err
}

// WriteNode writes a single node to the output
func (w *StreamingWriter) WriteNode(node *Node) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.inEdges {
		return fmt.Errorf("cannot write nodes after edges have started")
	}

	// Write comma if not first node
	if !w.firstNode {
		if _, err := w.file.WriteString(",\n"); err != nil {
			return err
		}
	}
	w.firstNode = false

	// Marshal and write the node
	data, err := json.Marshal(node)
	if err != nil {
		return err
	}

	if _, err := w.file.WriteString("      "); err != nil {
		return err
	}
	if _, err := w.file.Write(data); err != nil {
		return err
	}

	w.nodeCount++
	return nil
}

// WriteEdge writes a single edge to the output
func (w *StreamingWriter) WriteEdge(edge *Edge) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Transition from nodes to edges if needed
	if !w.inEdges {
		if err := w.transitionToEdges(); err != nil {
			return err
		}
	}

	// Write comma if not first edge
	if !w.firstEdge {
		if _, err := w.file.WriteString(",\n"); err != nil {
			return err
		}
	}
	w.firstEdge = false

	// Marshal and write the edge
	data, err := json.Marshal(edge)
	if err != nil {
		return err
	}

	if _, err := w.file.WriteString("      "); err != nil {
		return err
	}
	if _, err := w.file.Write(data); err != nil {
		return err
	}

	w.edgeCount++
	return nil
}

// transitionToEdges closes the nodes array and starts the edges array
func (w *StreamingWriter) transitionToEdges() error {
	transition := `
    ],
    "edges": [
`
	_, err := w.file.WriteString(transition)
	if err != nil {
		return err
	}
	w.inEdges = true
	return nil
}

// Close finalizes the JSON and closes the file
func (w *StreamingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// If we never wrote edges, transition now
	if !w.inEdges {
		if err := w.transitionToEdges(); err != nil {
			return err
		}
	}

	// Write footer
	footer := `
    ]
  }
}
`
	if _, err := w.file.WriteString(footer); err != nil {
		return err
	}

	return w.file.Close()
}

// Stats returns the number of nodes and edges written
func (w *StreamingWriter) Stats() (nodes, edges int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.nodeCount, w.edgeCount
}

// FilePath returns the path to the output file
func (w *StreamingWriter) FilePath() string {
	return w.filePath
}

// FileSize returns the current size of the output file
func (w *StreamingWriter) FileSize() (int64, error) {
	info, err := w.file.Stat()
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// NodeKinds defines the BloodHound node kinds for MSSQL objects
var NodeKinds = struct {
	Server          string
	Database        string
	Login           string
	ServerRole      string
	DatabaseUser    string
	DatabaseRole    string
	ApplicationRole string
	User            string
	Group           string
	Computer        string
}{
	Server:          "MSSQL_Server",
	Database:        "MSSQL_Database",
	Login:           "MSSQL_Login",
	ServerRole:      "MSSQL_ServerRole",
	DatabaseUser:    "MSSQL_DatabaseUser",
	DatabaseRole:    "MSSQL_DatabaseRole",
	ApplicationRole: "MSSQL_ApplicationRole",
	User:            "User",
	Group:           "Group",
	Computer:        "Computer",
}

// EdgeKinds defines the BloodHound edge kinds for MSSQL relationships
var EdgeKinds = struct {
	MemberOf             string
	IsMappedTo           string
	Contains             string
	Owns                 string
	ControlServer        string
	ControlDB            string
	Impersonate          string
	ImpersonateAnyLogin  string
	ChangePassword       string
	AddMember            string
	Alter                string
	Control              string
	ChangeOwner          string
	AlterAnyLogin        string
	AlterAnyServerRole   string
	AlterAnyRole         string
	AlterAnyDBRole       string
	AlterAnyAppRole      string
	GrantAnyPermission   string
	GrantAnyDBPermission string
	LinkedTo             string
	ExecuteAsOwner       string
	IsTrustedBy          string
	HasDBScopedCred      string
	HasMappedCred        string
	HasProxyCred         string
	ServiceAccountFor    string
	HostFor              string
	ExecuteOnHost        string
	TakeOwnership        string
	CanExecuteOnServer   string
	CanExecuteOnDB       string
	Connect              string
	ConnectAnyDatabase   string
	ExecuteAs            string
	HasLogin             string
	GetTGS               string
	GetAdminTGS          string
	HasSession           string
	LinkedAsAdmin        string
	CoerceAndRelayTo     string
}{
	MemberOf:             "MSSQL_MemberOf",
	IsMappedTo:           "MSSQL_IsMappedTo",
	Contains:             "MSSQL_Contains",
	Owns:                 "MSSQL_Owns",
	ControlServer:        "MSSQL_ControlServer",
	ControlDB:            "MSSQL_ControlDB",
	Impersonate:          "MSSQL_Impersonate",
	ImpersonateAnyLogin:  "MSSQL_ImpersonateAnyLogin",
	ChangePassword:       "MSSQL_ChangePassword",
	AddMember:            "MSSQL_AddMember",
	Alter:                "MSSQL_Alter",
	Control:              "MSSQL_Control",
	ChangeOwner:          "MSSQL_ChangeOwner",
	AlterAnyLogin:        "MSSQL_AlterAnyLogin",
	AlterAnyServerRole:   "MSSQL_AlterAnyServerRole",
	AlterAnyRole:         "MSSQL_AlterAnyRole",
	AlterAnyDBRole:       "MSSQL_AlterAnyDBRole",
	AlterAnyAppRole:      "MSSQL_AlterAnyAppRole",
	GrantAnyPermission:   "MSSQL_GrantAnyPermission",
	GrantAnyDBPermission: "MSSQL_GrantAnyDBPermission",
	LinkedTo:             "MSSQL_LinkedTo",
	ExecuteAsOwner:       "MSSQL_ExecuteAsOwner",
	IsTrustedBy:          "MSSQL_IsTrustedBy",
	HasDBScopedCred:      "MSSQL_HasDBScopedCred",
	HasMappedCred:        "MSSQL_HasMappedCred",
	HasProxyCred:         "MSSQL_HasProxyCred",
	ServiceAccountFor:    "MSSQL_ServiceAccountFor",
	HostFor:              "MSSQL_HostFor",
	ExecuteOnHost:        "MSSQL_ExecuteOnHost",
	TakeOwnership:        "MSSQL_TakeOwnership",
	CanExecuteOnServer:   "MSSQL_CanExecuteOnServer",
	CanExecuteOnDB:       "MSSQL_CanExecuteOnDB",
	Connect:              "MSSQL_Connect",
	ConnectAnyDatabase:   "MSSQL_ConnectAnyDatabase",
	ExecuteAs:            "MSSQL_ExecuteAs",
	HasLogin:             "MSSQL_HasLogin",
	GetTGS:               "MSSQL_GetTGS",
	GetAdminTGS:          "MSSQL_GetAdminTGS",
	HasSession:           "HasSession",
	LinkedAsAdmin:        "MSSQL_LinkedAsAdmin",
	CoerceAndRelayTo:     "CoerceAndRelayToMSSQL",
}

// Icons defines the default icons for MSSQL node types
var Icons = map[string]*Icon{
	NodeKinds.Server: {
		Type:  "font-awesome",
		Name:  "server",
		Color: "#42b9f5",
	},
	NodeKinds.Database: {
		Type:  "font-awesome",
		Name:  "database",
		Color: "#f54242",
	},
	NodeKinds.Login: {
		Type:  "font-awesome",
		Name:  "user-gear",
		Color: "#dd42f5",
	},
	NodeKinds.ServerRole: {
		Type:  "font-awesome",
		Name:  "users-gear",
		Color: "#6942f5",
	},
	NodeKinds.DatabaseUser: {
		Type:  "font-awesome",
		Name:  "user",
		Color: "#f5ef42",
	},
	NodeKinds.DatabaseRole: {
		Type:  "font-awesome",
		Name:  "users",
		Color: "#f5a142",
	},
	NodeKinds.ApplicationRole: {
		Type:  "font-awesome",
		Name:  "robot",
		Color: "#6ff542",
	},
}

// CopyIcon returns a copy of an icon
func CopyIcon(icon *Icon) *Icon {
	if icon == nil {
		return nil
	}
	return &Icon{
		Type:  icon.Type,
		Name:  icon.Name,
		Color: icon.Color,
	}
}

// WriteToFile writes the complete output to a file (non-streaming)
func WriteToFile(filePath string, nodes []Node, edges []Edge) error {
	output := struct {
		Schema   string `json:"$schema"`
		Metadata struct {
			SourceKind string `json:"source_kind"`
		} `json:"metadata"`
		Graph struct {
			Nodes []Node `json:"nodes"`
			Edges []Edge `json:"edges"`
		} `json:"graph"`
	}{
		Schema: "https://raw.githubusercontent.com/MichaelGrafnetter/EntraAuthPolicyHound/refs/heads/main/bloodhound-opengraph.schema.json",
	}
	output.Metadata.SourceKind = "MSSQL_Base"
	output.Graph.Nodes = nodes
	output.Graph.Edges = edges

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

// ReadFromFile reads BloodHound JSON from a file
func ReadFromFile(filePath string) ([]Node, []Edge, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	return ReadFrom(file)
}

// ReadFrom reads BloodHound JSON from a reader
func ReadFrom(r io.Reader) ([]Node, []Edge, error) {
	var output struct {
		Graph struct {
			Nodes []Node `json:"nodes"`
			Edges []Edge `json:"edges"`
		} `json:"graph"`
	}

	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&output); err != nil {
		return nil, nil, err
	}

	return output.Graph.Nodes, output.Graph.Edges, nil
}
