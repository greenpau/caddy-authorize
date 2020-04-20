package jwt

// AccessListEntry represent an access list entry.
type AccessListEntry struct {
	Action string   `json:"action,omitempty"`
	Roles  []string `json:"roles,omitempty"`
}
