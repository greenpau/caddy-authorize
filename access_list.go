package jwt

// AccessListEntry represent an access list entry.
type AccessListEntry struct {
	Action string   `json:"action,omitempty"`
	Values []string `json:"values,omitempty"`
	Claim  string   `json:"claim,omitempty"`
}
