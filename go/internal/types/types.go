// Package types defines the core data structures used throughout MSSQLHound.
// These types mirror the data structures from the PowerShell version and are
// used for SQL Server collection, BloodHound output, and Active Directory integration.
package types

import (
	"time"
)

// ServerInfo represents a SQL Server instance and all collected data
type ServerInfo struct {
	ObjectIdentifier      string                     `json:"objectIdentifier"`
	Hostname              string                     `json:"hostname"`
	ServerName            string                     `json:"serverName"`
	SQLServerName         string                     `json:"sqlServerName"` // Display name for BloodHound
	InstanceName          string                     `json:"instanceName"`
	Port                  int                        `json:"port"`
	Version               string                     `json:"version"`
	VersionNumber         string                     `json:"versionNumber"`
	ProductLevel          string                     `json:"productLevel"`
	Edition               string                     `json:"edition"`
	IsClustered           bool                       `json:"isClustered"`
	IsMixedModeAuth       bool                       `json:"isMixedModeAuth"`
	ForceEncryption       string                     `json:"forceEncryption,omitempty"`
	ExtendedProtection    string                     `json:"extendedProtection,omitempty"`
	ComputerSID           string                     `json:"computerSID"`
	DomainSID             string                     `json:"domainSID"`
	FQDN                  string                     `json:"fqdn"`
	SPNs                  []string                   `json:"spns,omitempty"`
	ServiceAccounts       []ServiceAccount           `json:"serviceAccounts,omitempty"`
	Credentials           []Credential               `json:"credentials,omitempty"`
	ProxyAccounts         []ProxyAccount             `json:"proxyAccounts,omitempty"`
	ServerPrincipals      []ServerPrincipal          `json:"serverPrincipals,omitempty"`
	Databases             []Database                 `json:"databases,omitempty"`
	LinkedServers         []LinkedServer             `json:"linkedServers,omitempty"`
	LocalGroupsWithLogins map[string]*LocalGroupInfo `json:"localGroupsWithLogins,omitempty"` // keyed by principal ObjectIdentifier
}

// LocalGroupInfo holds information about a local Windows group and its domain members
type LocalGroupInfo struct {
	Principal *ServerPrincipal   `json:"principal"`
	Members   []LocalGroupMember `json:"members,omitempty"`
}

// LocalGroupMember represents a domain member of a local Windows group
type LocalGroupMember struct {
	Domain string `json:"domain"`
	Name   string `json:"name"`
	SID    string `json:"sid,omitempty"`
}

// ServiceAccount represents a SQL Server service account
type ServiceAccount struct {
	ObjectIdentifier     string `json:"objectIdentifier"`
	Name                 string `json:"name"`
	ServiceName          string `json:"serviceName"`
	ServiceType          string `json:"serviceType"`
	StartupType          string `json:"startupType"`
	SID                  string `json:"sid,omitempty"`
	ConvertedFromBuiltIn bool   `json:"convertedFromBuiltIn,omitempty"` // True if converted from LocalSystem, NT AUTHORITY\*, etc.
}

// ServerPrincipal represents a server-level principal (login or server role)
type ServerPrincipal struct {
	ObjectIdentifier           string           `json:"objectIdentifier"`
	PrincipalID                int              `json:"principalId"`
	Name                       string           `json:"name"`
	TypeDescription            string           `json:"typeDescription"`
	IsDisabled                 bool             `json:"isDisabled"`
	IsFixedRole                bool             `json:"isFixedRole"`
	CreateDate                 time.Time        `json:"createDate"`
	ModifyDate                 time.Time        `json:"modifyDate"`
	DefaultDatabaseName        string           `json:"defaultDatabaseName,omitempty"`
	SecurityIdentifier         string           `json:"securityIdentifier,omitempty"`
	IsActiveDirectoryPrincipal bool             `json:"isActiveDirectoryPrincipal"`
	SQLServerName              string           `json:"sqlServerName"`
	OwningPrincipalID          int              `json:"owningPrincipalId,omitempty"`
	OwningObjectIdentifier     string           `json:"owningObjectIdentifier,omitempty"`
	MemberOf                   []RoleMembership `json:"memberOf,omitempty"`
	Members                    []string         `json:"members,omitempty"`
	Permissions                []Permission     `json:"permissions,omitempty"`
	DatabaseUsers              []string         `json:"databaseUsers,omitempty"`
	MappedCredential           *Credential      `json:"mappedCredential,omitempty"` // Credential mapped via ALTER LOGIN ... WITH CREDENTIAL
}

// RoleMembership represents membership in a role
type RoleMembership struct {
	ObjectIdentifier string `json:"objectIdentifier"`
	Name             string `json:"name,omitempty"`
	PrincipalID      int    `json:"principalId,omitempty"`
}

// Permission represents a granted or denied permission
type Permission struct {
	Permission             string `json:"permission"`
	State                  string `json:"state"` // GRANT, GRANT_WITH_GRANT_OPTION, DENY
	ClassDesc              string `json:"classDesc"`
	TargetPrincipalID      int    `json:"targetPrincipalId,omitempty"`
	TargetObjectIdentifier string `json:"targetObjectIdentifier,omitempty"`
	TargetName             string `json:"targetName,omitempty"`
}

// Database represents a SQL Server database
type Database struct {
	ObjectIdentifier      string               `json:"objectIdentifier"`
	DatabaseID            int                  `json:"databaseId"`
	Name                  string               `json:"name"`
	OwnerPrincipalID      int                  `json:"ownerPrincipalId,omitempty"`
	OwnerLoginName        string               `json:"ownerLoginName,omitempty"`
	OwnerObjectIdentifier string               `json:"ownerObjectIdentifier,omitempty"`
	CreateDate            time.Time            `json:"createDate"`
	CompatibilityLevel    int                  `json:"compatibilityLevel"`
	CollationName         string               `json:"collationName,omitempty"`
	IsReadOnly            bool                 `json:"isReadOnly"`
	IsTrustworthy         bool                 `json:"isTrustworthy"`
	IsEncrypted           bool                 `json:"isEncrypted"`
	SQLServerName         string               `json:"sqlServerName"`
	DatabasePrincipals    []DatabasePrincipal  `json:"databasePrincipals,omitempty"`
	DBScopedCredentials   []DBScopedCredential `json:"dbScopedCredentials,omitempty"`
}

// DatabasePrincipal represents a database-level principal
type DatabasePrincipal struct {
	ObjectIdentifier       string           `json:"objectIdentifier"`
	PrincipalID            int              `json:"principalId"`
	Name                   string           `json:"name"`
	TypeDescription        string           `json:"typeDescription"`
	CreateDate             time.Time        `json:"createDate"`
	ModifyDate             time.Time        `json:"modifyDate"`
	IsFixedRole            bool             `json:"isFixedRole"`
	OwningPrincipalID      int              `json:"owningPrincipalId,omitempty"`
	OwningObjectIdentifier string           `json:"owningObjectIdentifier,omitempty"`
	DefaultSchemaName      string           `json:"defaultSchemaName,omitempty"`
	DatabaseName           string           `json:"databaseName"`
	SQLServerName          string           `json:"sqlServerName"`
	ServerLogin            *ServerLoginRef  `json:"serverLogin,omitempty"`
	MemberOf               []RoleMembership `json:"memberOf,omitempty"`
	Members                []string         `json:"members,omitempty"`
	Permissions            []Permission     `json:"permissions,omitempty"`
}

// ServerLoginRef is a reference to a server login from a database user
type ServerLoginRef struct {
	ObjectIdentifier string `json:"objectIdentifier"`
	Name             string `json:"name"`
	PrincipalID      int    `json:"principalId"`
}

// DBScopedCredential represents a database-scoped credential
type DBScopedCredential struct {
	CredentialID       int       `json:"credentialId"`
	Name               string    `json:"name"`
	CredentialIdentity string    `json:"credentialIdentity"`
	CreateDate         time.Time `json:"createDate"`
	ModifyDate         time.Time `json:"modifyDate"`
	ResolvedSID        string    `json:"resolvedSid,omitempty"` // Resolved AD SID for the credential identity
}

// LinkedServer represents a linked server configuration
type LinkedServer struct {
	ServerID                     int    `json:"serverId"`
	Name                         string `json:"name"`
	Product                      string `json:"product"`
	Provider                     string `json:"provider"`
	DataSource                   string `json:"dataSource"`
	Catalog                      string `json:"catalog,omitempty"`
	IsLinkedServer               bool   `json:"isLinkedServer"`
	IsRemoteLoginEnabled         bool   `json:"isRemoteLoginEnabled"`
	IsRPCOutEnabled              bool   `json:"isRpcOutEnabled"`
	IsDataAccessEnabled          bool   `json:"isDataAccessEnabled"`
	LocalLogin                   string `json:"localLogin,omitempty"`
	RemoteLogin                  string `json:"remoteLogin,omitempty"`
	IsSelfMapping                bool   `json:"isSelfMapping"`
	ResolvedObjectIdentifier     string `json:"resolvedObjectIdentifier,omitempty"` // Target server ObjectIdentifier
	RemoteIsSysadmin             bool   `json:"remoteIsSysadmin,omitempty"`
	RemoteIsSecurityAdmin        bool   `json:"remoteIsSecurityAdmin,omitempty"`
	RemoteHasControlServer       bool   `json:"remoteHasControlServer,omitempty"`
	RemoteHasImpersonateAnyLogin bool   `json:"remoteHasImpersonateAnyLogin,omitempty"`
	RemoteIsMixedMode            bool   `json:"remoteIsMixedMode,omitempty"`
	UsesImpersonation            bool   `json:"usesImpersonation,omitempty"`
}

// ProxyAccount represents a SQL Agent proxy account
type ProxyAccount struct {
	ProxyID            int      `json:"proxyId"`
	Name               string   `json:"name"`
	CredentialID       int      `json:"credentialId"`
	CredentialIdentity string   `json:"credentialIdentity"`
	Enabled            bool     `json:"enabled"`
	Description        string   `json:"description,omitempty"`
	Subsystems         []string `json:"subsystems,omitempty"`
	Logins             []string `json:"logins,omitempty"`
	ResolvedSID        string   `json:"resolvedSid,omitempty"` // Resolved AD SID for the credential identity
}

// Credential represents a server-level credential
type Credential struct {
	CredentialID       int       `json:"credentialId"`
	Name               string    `json:"name"`
	CredentialIdentity string    `json:"credentialIdentity"`
	CreateDate         time.Time `json:"createDate"`
	ModifyDate         time.Time `json:"modifyDate"`
	ResolvedSID        string    `json:"resolvedSid,omitempty"` // Resolved AD SID for the credential identity
}

// DomainPrincipal represents a resolved Active Directory principal
type DomainPrincipal struct {
	ObjectIdentifier  string   `json:"objectIdentifier"`
	SID               string   `json:"sid"`
	Name              string   `json:"name"`
	SAMAccountName    string   `json:"samAccountName,omitempty"`
	DistinguishedName string   `json:"distinguishedName,omitempty"`
	Domain            string   `json:"domain"`
	ObjectClass       string   `json:"objectClass"` // user, group, computer
	Enabled           bool     `json:"enabled"`
	MemberOf          []string `json:"memberOf,omitempty"`
}

// SPN represents a Service Principal Name
type SPN struct {
	ServiceClass string `json:"serviceClass"`
	Hostname     string `json:"hostname"`
	Port         string `json:"port,omitempty"`
	InstanceName string `json:"instanceName,omitempty"`
	FullSPN      string `json:"fullSpn"`
	AccountName  string `json:"accountName"`
	AccountSID   string `json:"accountSid"`
}
