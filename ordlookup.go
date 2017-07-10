package pe

import (
	"fmt"
	"strings"
)

// OrdLookup returns known names for unnamed import
func OrdLookup(libName string, ord uint64, makeName bool) string {
	libName = strings.ToLower(libName)
	var names map[uint64]string
	switch libName {
	case "ws2_32.dll", "wsock32.dll":
		names = Ws32OrdNames
	case "oleaut32.dll":
		names = OLEAUT_32_ORD_NAMES
	default:
		return ""
	}
	if names != nil {
		if name, ok := names[ord]; ok {
			return name
		}
	}
	if makeName {
		return fmt.Sprintf("ord%d", ord)
	}
	return ""
}
