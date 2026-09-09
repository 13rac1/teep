package nearparse

// Info retains all supported fields of model and gateway info.
type Info struct {
	AppName         string `json:"app_name"`
	ComposeHash     string `json:"compose_hash"`
	OSImageHash     string `json:"os_image_hash"`
	DeviceID        string `json:"device_id"`
	AppCert         string `json:"app_cert,omitempty"`
	AppID           string `json:"app_id,omitempty"`
	InstanceID      string `json:"instance_id,omitempty"`
	KeyProviderInfo string `json:"key_provider_info,omitempty"`
	MRAggregated    string `json:"mr_aggregated,omitempty"`
	VMConfig        string `json:"vm_config,omitempty"`
	TCBInfo         TCB    `json:"tcb_info"`
}

// TCB retains the complete supported TCB structure, including its event log.
type TCB struct {
	AppCompose  string   `json:"app_compose"`
	ComposeHash string   `json:"compose_hash,omitempty"`
	DeviceID    string   `json:"device_id,omitempty"`
	OSImageHash string   `json:"os_image_hash,omitempty"`
	MRTD        string   `json:"mrtd,omitempty"`
	RTMR0       string   `json:"rtmr0,omitempty"`
	RTMR1       string   `json:"rtmr1,omitempty"`
	RTMR2       string   `json:"rtmr2,omitempty"`
	RTMR3       string   `json:"rtmr3,omitempty"`
	EventLog    EventLog `json:"event_log,omitempty"`
	unknown     []string
}

// UnmarshalJSON validates the supported object or one JSON-string layer.
func (t *TCB) UnmarshalJSON(data []byte) error {
	object, err := EncodedObject(data)
	if err != nil {
		return err
	}
	type fields TCB
	var out fields
	unknown, err := Object(object, &out, "tcb_info")
	if err != nil {
		return err
	}
	unknown = append(unknown, out.EventLog.UnknownFields("tcb_info.event_log")...)
	out.unknown = unknown
	*t = TCB(out)
	return nil
}

// DecodedInfo contains the validated info structure and its field diagnostics.
type DecodedInfo struct {
	Info    Info
	unknown []string
}

// UnmarshalJSON validates info before publishing any decoded fields.
func (d *DecodedInfo) UnmarshalJSON(data []byte) error {
	var info Info
	unknown, err := Object(data, &info, "info")
	if err != nil {
		return err
	}
	*d = DecodedInfo{Info: info, unknown: append(unknown, Prefix("info", info.TCBInfo.unknown)...)}
	return nil
}

// UnknownFields returns independent fully qualified diagnostic paths.
func (d *DecodedInfo) UnknownFields(parent string) []string { return Prefix(parent, d.unknown) }
