package dns

type DNSTurnaroud struct {
	Name         string
	Records      []string
	LatencyNS    int64
	Client       string
	Server       string
	ResponseCode uint16
}
