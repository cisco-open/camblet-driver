package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"samples/dns"

	json "github.com/mailru/easyjson"
	"golang.org/x/net/dns/dnsmessage"
)

//export submit_metric
func submit_metric(metric string) int32

//export _debug
func _debug(m string) int32

//export clock_ns
func clock_ns() int64

var dnsMessages = map[int32]dns.DNSTurnaroud{}

func int2ip(nn int32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, uint32(nn))
	return ip
}

//export dns_query
func dns_query(id int32, source int32, destination int32, dns_packet []byte) {

	timestamp := clock_ns()

	client := int2ip(source)
	server := int2ip(destination)

	_debug(fmt.Sprintf("wasm3: (%d bytes) %d: dns_query %d -> source ip: %s, destination ip: %s",
		len(dns_packet),
		timestamp,
		id,
		client,
		server,
	))

	var parser dnsmessage.Parser

	header, err := parser.Start(dns_packet)
	if err != nil {
		_debug("failed to parse dns header: " + err.Error())
		return
	}

	_debug("parsed query dns header: " + header.GoString())

	question, err := parser.Question()
	if err != nil {
		_debug("failed to parse dns question: " + err.Error())
		return
	}

	dnsMessages[id] = dns.DNSTurnaroud{
		Name:         strings.TrimSuffix(question.Name.String(), "."),
		LatencyNS:    timestamp,
		Client:       client.String(),
		Server:       server.String(),
		ResponseCode: uint16(header.RCode),
	}
}

//export dns_response
func dns_response(id int32, source int32, destination int32, dns_packet []byte) {

	timestamp := clock_ns()

	client := int2ip(source)
	server := int2ip(destination)

	_debug(fmt.Sprintf("wasm3: (%d bytes) %d: dns_response %d -> source ip: %s, destination ip: %s",
		len(dns_packet),
		timestamp,
		id,
		client,
		server,
	))

	var parser dnsmessage.Parser

	header, err := parser.Start(dns_packet)
	if err != nil {
		_debug("failed to parse dns header: " + err.Error())
		return
	}

	_debug("parsed answer dns header: " + header.GoString())

	t, ok := dnsMessages[id]
	if !ok {
		return
	}

	t.LatencyNS = timestamp - t.LatencyNS
	t.ResponseCode = uint16(header.RCode)

	for {
		_, err = parser.Question()
		if err != nil {
			if isSectionDone(err) {
				break
			}
			_debug("failed to skip dns question: " + err.Error())
			return
		}
	}

	_debug("skipped all dns questions in answer")

	for {
		h, err := parser.AnswerHeader()
		if err != nil {
			if err.Error() == dnsmessage.ErrSectionDone.Error() {
				break
			}
			_debug("failed to skip dns answer header: " + err.Error())
			return
		}

		_debug("answer header: " + h.Type.String())

		switch h.Type {
		case dnsmessage.TypeA:
			r, err := parser.AResource()
			if err != nil {
				_debug("failed to parse dns answer resource: " + err.Error())
				return
			}
			_debug("parsed AResource: " + r.GoString())

			t.Records = append(t.Records, net.IP(r.A[:]).String())
		case dnsmessage.TypeAAAA:
			r, err := parser.AAAAResource()
			if err != nil {
				_debug("failed to parse dns answer resource: " + err.Error())
				return
			}
			_debug("parsed AAAAResource: " + r.GoString())

			t.Records = append(t.Records, net.IP(r.AAAA[:]).String())
		}
	}

	metric, err := json.Marshal(t)
	if err != nil {
		_debug("failed to marhshal metric to json: " + err.Error())
		return
	}

	submit_metric(string(metric))

	delete(dnsMessages, id)
}

func isSectionDone(err error) bool {
	return err.Error() == dnsmessage.ErrSectionDone.Error()
}
