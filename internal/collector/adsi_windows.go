//go:build windows

package collector

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/SpecterOps/MSSQLHound/internal/logging"
	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

const adsiPageSize = 1000
const adsiProgressInterval = 10 * time.Second

func (c *Collector) enumerateComputersViaWindowsADSI() ([]domainComputer, error) {
	c.config.Logger.Info("Using Go ADSI fallback for computer enumeration")

	baseDN := adsiDomainToDN(c.config.Domain)
	if baseDN == "" {
		return nil, fmt.Errorf("domain is required for ADSI computer enumeration")
	}

	if err := initializeCOMForADSI(); err != nil {
		return nil, err
	}
	defer ole.CoUninitialize()

	connectionUnknown, err := oleutil.CreateObject("ADODB.Connection")
	if err != nil {
		return nil, fmt.Errorf("create ADODB connection: %w", err)
	}
	defer connectionUnknown.Release()

	connection, err := connectionUnknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return nil, fmt.Errorf("query ADODB connection interface: %w", err)
	}
	defer connection.Release()

	if result, err := oleutil.CallMethod(connection, "Open", "Provider=ADsDSOObject;"); err != nil {
		return nil, fmt.Errorf("open ADSI provider: %w", err)
	} else if result != nil {
		defer result.Clear()
	}
	defer oleutil.CallMethod(connection, "Close")

	commandUnknown, err := oleutil.CreateObject("ADODB.Command")
	if err != nil {
		return nil, fmt.Errorf("create ADODB command: %w", err)
	}
	defer commandUnknown.Release()

	command, err := commandUnknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return nil, fmt.Errorf("query ADODB command interface: %w", err)
	}
	defer command.Release()

	if result, err := oleutil.PutPropertyRef(command, "ActiveConnection", connection); err != nil {
		return nil, fmt.Errorf("set ADSI active connection: %w", err)
	} else if result != nil {
		result.Clear()
	}

	query := fmt.Sprintf("<LDAP://%s>;(&(objectCategory=computer)(objectClass=computer));dNSHostName,name,objectSid;subtree", baseDN)
	if result, err := oleutil.PutProperty(command, "CommandText", query); err != nil {
		return nil, fmt.Errorf("set ADSI command text: %w", err)
	} else if result != nil {
		result.Clear()
	}

	if err := setADOCommandProperty(command, "Page Size", adsiPageSize); err != nil {
		return nil, err
	}
	if err := setADOCommandProperty(command, "Timeout", 30); err != nil {
		return nil, err
	}
	if err := setADOCommandProperty(command, "Cache Results", false); err != nil {
		return nil, err
	}

	c.config.Logger.Info("Executing Go ADSI computer query", "baseDN", baseDN, "pageSize", adsiPageSize)
	recordsetVar, err := oleutil.CallMethod(command, "Execute")
	if err != nil {
		return nil, fmt.Errorf("execute ADSI computer query: %w", err)
	}
	defer recordsetVar.Clear()

	recordset := recordsetVar.ToIDispatch()
	if recordset == nil {
		return nil, fmt.Errorf("execute ADSI computer query returned no recordset")
	}
	defer recordset.Release()
	defer oleutil.CallMethod(recordset, "Close")

	c.config.Logger.Info("Reading Go ADSI computer results")
	computers, err := c.readADSIComputerRecordset(recordset, c.config.Domain)
	if err != nil {
		return nil, err
	}

	c.config.Logger.Log(context.Background(), logging.LevelVerbose, "Go ADSI enumerated domain computers", "count", len(computers))
	return computers, nil
}

func initializeCOMForADSI() error {
	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		oleErr, ok := err.(*ole.OleError)
		if !ok || oleErr.Code() != 1 {
			return fmt.Errorf("COM initialization failed: %w", err)
		}
	}
	return nil
}

func setADOCommandProperty(command *ole.IDispatch, name string, value interface{}) error {
	propertiesVar, err := oleutil.GetProperty(command, "Properties")
	if err != nil {
		return fmt.Errorf("get ADSI command properties: %w", err)
	}
	defer propertiesVar.Clear()

	properties := propertiesVar.ToIDispatch()
	if properties == nil {
		return fmt.Errorf("get ADSI command properties: no dispatch returned")
	}
	defer properties.Release()

	propertyVar, err := adoCollectionItem(properties, name)
	if err != nil {
		return fmt.Errorf("get ADSI command property %q: %w", name, err)
	}
	defer propertyVar.Clear()

	property := propertyVar.ToIDispatch()
	if property == nil {
		return fmt.Errorf("get ADSI command property %q: no dispatch returned", name)
	}
	defer property.Release()

	if result, err := oleutil.PutProperty(property, "Value", value); err != nil {
		return fmt.Errorf("set ADSI command property %q: %w", name, err)
	} else if result != nil {
		result.Clear()
	}

	return nil
}

func (c *Collector) readADSIComputerRecordset(recordset *ole.IDispatch, domain string) ([]domainComputer, error) {
	var computers []domainComputer
	started := time.Now()
	lastProgress := started

	for {
		eofVar, err := oleutil.GetProperty(recordset, "EOF")
		if err != nil {
			return nil, fmt.Errorf("read ADSI recordset EOF: %w", err)
		}
		eof := variantBool(eofVar)
		eofVar.Clear()
		if eof {
			break
		}

		fieldsVar, err := oleutil.GetProperty(recordset, "Fields")
		if err != nil {
			return nil, fmt.Errorf("read ADSI recordset fields: %w", err)
		}
		fields := fieldsVar.ToIDispatch()
		if fields == nil {
			fieldsVar.Clear()
			return nil, fmt.Errorf("read ADSI recordset fields: no dispatch returned")
		}

		dnsName := strings.TrimSpace(adsiFieldString(fields, "dNSHostName"))
		name := strings.TrimSpace(adsiFieldString(fields, "name"))
		if hostname := adsiComputerHostname(dnsName, name, domain); hostname != "" {
			computers = append(computers, domainComputer{
				Hostname: hostname,
				SID:      decodeBinarySID(adsiFieldBytes(fields, "objectSid")),
			})
		}

		fields.Release()
		fieldsVar.Clear()

		if result, err := oleutil.CallMethod(recordset, "MoveNext"); err != nil {
			return nil, fmt.Errorf("advance ADSI recordset: %w", err)
		} else if result != nil {
			result.Clear()
		}

		count := len(computers)
		if count > 0 && (count%1000 == 0 || time.Since(lastProgress) >= adsiProgressInterval) {
			c.config.Logger.Info("Enumerated domain computers via Go ADSI", "count", count, "elapsed", time.Since(started).Round(time.Second))
			lastProgress = time.Now()
		}
	}

	c.config.Logger.Info("Finished Go ADSI computer enumeration", "count", len(computers), "elapsed", time.Since(started).Round(time.Second))
	return computers, nil
}

func adsiFieldString(fields *ole.IDispatch, name string) string {
	fieldVar, err := adoCollectionItem(fields, name)
	if err != nil {
		return ""
	}
	defer fieldVar.Clear()

	field := fieldVar.ToIDispatch()
	if field == nil {
		return ""
	}
	defer field.Release()

	valueVar, err := oleutil.GetProperty(field, "Value")
	if err != nil {
		return ""
	}
	defer valueVar.Clear()

	if value, ok := valueVar.Value().(string); ok {
		return value
	}
	return valueVar.ToString()
}

func adsiFieldBytes(fields *ole.IDispatch, name string) []byte {
	fieldVar, err := adoCollectionItem(fields, name)
	if err != nil {
		return nil
	}
	defer fieldVar.Clear()

	field := fieldVar.ToIDispatch()
	if field == nil {
		return nil
	}
	defer field.Release()

	valueVar, err := oleutil.GetProperty(field, "Value")
	if err != nil {
		return nil
	}
	defer valueVar.Clear()

	array := valueVar.ToArray()
	if array == nil {
		return nil
	}
	return array.ToByteArray()
}

func adoCollectionItem(collection *ole.IDispatch, name string) (*ole.VARIANT, error) {
	itemVar, err := oleutil.GetProperty(collection, "Item", name)
	if err == nil {
		return itemVar, nil
	}
	return oleutil.CallMethod(collection, "Item", name)
}

func variantBool(value *ole.VARIANT) bool {
	if value == nil {
		return false
	}
	if boolValue, ok := value.Value().(bool); ok {
		return boolValue
	}
	return value.Val != 0
}

func decodeBinarySID(sidBytes []byte) string {
	if len(sidBytes) < 8 {
		return ""
	}

	revision := sidBytes[0]
	subAuthorityCount := int(sidBytes[1])
	if len(sidBytes) < 8+subAuthorityCount*4 {
		return ""
	}

	var authority uint64
	for i := 2; i < 8; i++ {
		authority = (authority << 8) | uint64(sidBytes[i])
	}

	sid := fmt.Sprintf("S-%d-%d", revision, authority)
	for i := 0; i < subAuthorityCount; i++ {
		offset := 8 + i*4
		subAuthority := uint32(sidBytes[offset]) |
			uint32(sidBytes[offset+1])<<8 |
			uint32(sidBytes[offset+2])<<16 |
			uint32(sidBytes[offset+3])<<24
		sid += fmt.Sprintf("-%d", subAuthority)
	}

	return sid
}

func adsiComputerHostname(dnsName, name, domain string) string {
	if dnsName != "" {
		return dnsName
	}
	if name == "" {
		return ""
	}
	if strings.Contains(name, ".") || domain == "" {
		return name
	}
	return name + "." + domain
}

func adsiDomainToDN(domain string) string {
	parts := strings.Split(domain, ".")
	dnParts := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			dnParts = append(dnParts, "DC="+part)
		}
	}
	return strings.Join(dnParts, ",")
}
