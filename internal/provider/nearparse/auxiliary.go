package nearparse

// OHTTP holds the supported auxiliary key-attestation fields. Its presence does
// not authenticate a model key or enable OHTTP inference in Teep.
type OHTTP struct {
	SigningAlgo string `json:"signing_algo"`
	SigningKey  string `json:"signing_key"`
	KeyConfig   string `json:"key_config"`
	Signature   string `json:"signature"`
	unknown     []string
}

// UnmarshalJSON validates the auxiliary object before assigning its fields.
func (o *OHTTP) UnmarshalJSON(data []byte) error {
	type fields OHTTP
	var out fields
	unknown, err := Object(data, &out, "ohttp_attestation")
	if err != nil {
		return err
	}
	out.unknown = unknown
	*o = OHTTP(out)
	return nil
}

// UnknownFields returns diagnostics without changing their policy.
func (o *OHTTP) UnknownFields(parent string) []string {
	if o == nil {
		return nil
	}
	return Prefix(parent, o.unknown)
}
