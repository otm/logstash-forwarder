package main

// Support for newer SSL signature algorithms
import (
	"bytes"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"regexp"
	"strconv"
	"time"
)

import (
	"compress/zlib"
	_ "crypto/sha512"
	"crypto/tls"
	"crypto/x509"
)
import _ "crypto/sha256"

func init() {
	rand.Seed(time.Now().UnixNano())
}

// LumberjackPublisher sends data to remote host via the lumberjack protocoll
type LumberjackPublisher struct {
	hostname      string
	hostportRegex *regexp.Regexp
	config        NetworkConfig
	socket        *tls.Conn
}

// NewLumberjackPublisher creates a new lumberjack instance
func NewLumberjackPublisher(netConf NetworkConfig) *LumberjackPublisher {
	hostname, _ := os.Hostname()

	lp := LumberjackPublisher{
		hostportRegex: regexp.MustCompile("^(.+):([0-9]+)$"),
		hostname:      hostname,
		config:        netConf,
	}

	return &lp
}

// Run will start to process the input chanel and send it to the remote host
func (lp *LumberjackPublisher) Run(input chan []*FileEvent, registrar chan []*FileEvent) {
	var buffer bytes.Buffer
	var sequence uint32

	lp.socket = lp.connect()
	defer lp.socket.Close()

	for events := range input {
		buffer.Truncate(0)
		compressor, _ := zlib.NewWriterLevel(&buffer, 3)

		for _, event := range events {
			sequence++
			writeDataFrame(event, sequence, compressor)
		}

		compressor.Flush()
		compressor.Close()

		compressedPayload := buffer.Bytes()

		lp.send(uint32(len(events)), compressedPayload)

		// Tell the registrar that we've successfully sent these events
		registrar <- events
	} /* for each event payload */
} // Publish

func (lp *LumberjackPublisher) oops(err error) {
	// TODO(sissel): Track how frequently we timeout and reconnect. If we're
	// timing out too frequently, there's really no point in timing out since
	// basically everything is slow or down. We'll want to ratchet up the
	// timeout value slowly until things improve, then ratchet it down once
	// things seem healthy.
	emit("Socket error, will reconnect: %s\n", err)
	time.Sleep(1 * time.Second)
	lp.socket.Close()
	lp.socket = lp.connect()
}

func (lp *LumberjackPublisher) send(events uint32, payload []byte) {
	for {
		// Abort if our whole request takes longer than the configured
		// network timeout.
		lp.socket.SetDeadline(time.Now().Add(lp.config.timeout))

		// Set the window size to the length of this payload in events.
		_, err := lp.socket.Write([]byte("1W"))
		if err != nil {
			lp.oops(err)
			continue
		}
		binary.Write(lp.socket, binary.BigEndian, events)
		if err != nil {
			lp.oops(err)
			continue
		}

		// Write compressed frame
		lp.socket.Write([]byte("1C"))
		if err != nil {
			lp.oops(err)
			continue
		}
		binary.Write(lp.socket, binary.BigEndian, uint32(len(payload)))
		if err != nil {
			lp.oops(err)
			continue
		}
		_, err = lp.socket.Write(payload)
		if err != nil {
			lp.oops(err)
			continue
		}

		// read ack
		response := make([]byte, 0, 6)
		ackbytes := 0
		for ackbytes != 6 {
			n, err := lp.socket.Read(response[len(response):cap(response)])
			if err != nil {
				emit("Read error looking for ack: %s\n", err)
				lp.socket.Close()
				lp.socket = lp.connect()
				continue // retry sending on new connection
			} else {
				ackbytes += n
			}
		}

		// TODO(sissel): verify ack
		// Success, stop trying to send the payload.
		return
	}

}

func (lp *LumberjackPublisher) connect() (socket *tls.Conn) {
	var tlsconfig tls.Config
	tlsconfig.MinVersion = tls.VersionTLS10

	if len(lp.config.SSLCertificate) > 0 && len(lp.config.SSLKey) > 0 {
		emit("Loading client ssl certificate: %s and %s\n",
			lp.config.SSLCertificate, lp.config.SSLKey)
		cert, err := tls.LoadX509KeyPair(lp.config.SSLCertificate, lp.config.SSLKey)
		if err != nil {
			fault("Failed loading client ssl certificate: %s\n", err)
		}
		tlsconfig.Certificates = []tls.Certificate{cert}
	}

	if len(lp.config.SSLCA) > 0 {
		emit("Setting trusted CA from file: %s\n", lp.config.SSLCA)
		tlsconfig.RootCAs = x509.NewCertPool()

		pemdata, err := ioutil.ReadFile(lp.config.SSLCA)
		if err != nil {
			fault("Failure reading CA certificate: %s\n", err)
		}

		block, _ := pem.Decode(pemdata)
		if block == nil {
			fault("Failed to decode PEM data, is %s a valid cert?\n", lp.config.SSLCA)
		}
		if block.Type != "CERTIFICATE" {
			fault("This is not a certificate file: %s\n", lp.config.SSLCA)
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			fault("Failed to parse a certificate: %s\n", lp.config.SSLCA)
		}
		tlsconfig.RootCAs.AddCert(cert)
	}

	for {
		// Pick a random server from the list.
		hostport := lp.config.Servers[rand.Int()%len(lp.config.Servers)]
		submatch := hostport_re.FindSubmatch([]byte(hostport))
		if submatch == nil {
			fault("Invalid host:port given: %s", hostport)
		}
		host := string(submatch[1])
		port := string(submatch[2])
		addresses, err := net.LookupHost(host)

		if err != nil {
			emit("DNS lookup failure \"%s\": %s\n", host, err)
			time.Sleep(1 * time.Second)
			continue
		}

		address := addresses[rand.Int()%len(addresses)]
		var addressport string

		ip := net.ParseIP(address)
		if len(ip) == net.IPv4len {
			addressport = fmt.Sprintf("%s:%s", address, port)
		} else if len(ip) == net.IPv6len {
			addressport = fmt.Sprintf("[%s]:%s", address, port)
		}

		emit("Connecting to %s (%s) \n", addressport, host)

		tcpsocket, err := net.DialTimeout("tcp", addressport, lp.config.timeout)
		if err != nil {
			emit("Failure connecting to %s: %s\n", address, err)
			time.Sleep(1 * time.Second)
			continue
		}

		tlsconfig.ServerName = host

		socket = tls.Client(tcpsocket, &tlsconfig)
		socket.SetDeadline(time.Now().Add(lp.config.timeout))
		err = socket.Handshake()
		if err != nil {
			emit("Failed to tls handshake with %s %s\n", address, err)
			time.Sleep(1 * time.Second)
			socket.Close()
			continue
		}

		emit("Connected to %s\n", address)

		// connected, let's rock and roll.
		return
	}

}

func (lp *LumberjackPublisher) writeDataFrame(event *FileEvent, sequence uint32, output io.Writer) {
	// header, "1D"
	output.Write([]byte("1D"))

	// sequence number
	binary.Write(output, binary.BigEndian, uint32(sequence))

	// 'pair' count
	binary.Write(output, binary.BigEndian, uint32(len(*event.Fields)+4))

	lp.writeKV("file", *event.Source, output)
	lp.writeKV("host", hostname, output)
	lp.writeKV("offset", strconv.FormatInt(event.Offset, 10), output)
	lp.writeKV("line", *event.Text, output)
	for k, v := range *event.Fields {
		lp.writeKV(k, v, output)
	}
}

func (lp *LumberjackPublisher) writeKV(key string, value string, output io.Writer) {
	binary.Write(output, binary.BigEndian, uint32(len(key)))
	output.Write([]byte(key))
	binary.Write(output, binary.BigEndian, uint32(len(value)))
	output.Write([]byte(value))
}
