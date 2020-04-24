package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"os"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/network"
	host "github.com/libp2p/go-libp2p-host"
	libp2pquic "github.com/libp2p/go-libp2p-quic-transport"
	routing "github.com/libp2p/go-libp2p-routing"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	logging "github.com/whyrusleeping/go-logging"

	"github.com/ipfs/go-log"
)

var logger = log.Logger("rendezvous")

func getPrivateKey() crypto.PrivKey {
	const (
		keyFileName = "prv.key"
	)
	keyFile, err := os.Open(keyFileName)
	var prvKey crypto.PrivKey
	if err != nil {
		// Creates a new RSA key pair for this host.
		prvKey, _, err := crypto.GenerateKeyPairWithReader(crypto.RSA, 2048, rand.Reader)
		if err != nil {
			panic(err)
		}
		keyBytes, err := crypto.MarshalPrivateKey(prvKey)
		if err != nil {
			panic(err)
		}
		keyFile, err = os.Create(keyFileName)
		if err != nil {
			panic(err)
		}
		err = binary.Write(keyFile, binary.LittleEndian, keyBytes)
		if err != nil {
			panic(err)
		}
	} else {
		fileStats, err := keyFile.Stat()
		if err != nil {
			panic(err)
		}
		keyBytes := make([]byte, fileStats.Size())
		err = binary.Read(keyFile, binary.LittleEndian, keyBytes)
		if err != nil {
			panic(err)
		}
		prvKey, err = crypto.UnmarshalPrivateKey(keyBytes)
		if err != nil {
			panic(err)
		}
	}
	return prvKey
}

func main() {
	log.SetAllLoggers(logging.WARNING)
	log.SetLogLevel("rendezvous", "debug")
	var err error

	ctx := context.Background()

	var kademliaDHT *dht.IpfsDHT

	// libp2p.New constructs a new libp2p Host. Other options can be added
	// here.
	host, err := libp2p.New(ctx,
		libp2p.ListenAddrStrings(
			"/ip4/0.0.0.0/tcp/9999",      // regular tcp connections
			"/ip4/0.0.0.0/udp/9999/quic", // a UDP endpoint for the QUIC transport
		),
		libp2p.Transport(libp2pquic.NewTransport),
		libp2p.DefaultTransports,
		// libp2p.EnableAutoRelay(),
		libp2p.Identity(getPrivateKey()),
		libp2p.Routing(func(h host.Host) (routing.PeerRouting, error) {
			kademliaDHT, err = dht.New(ctx, h)
			return kademliaDHT, err
		}),
	)
	if err != nil {
		panic(err)
	}
	logger.Info("Host created. We are:", host.ID())
	logger.Info(host.Addrs())

	host.Network().SetConnHandler(func(con network.Conn) {
		logger.Debug("Peer connected:", con)
		host.Peerstore().AddAddr(con.RemotePeer(), con.RemoteMultiaddr(), time.Minute)
	})

	// kademliaDHT.RoutingTable().PeerAdded = func(id peer.ID) {
	// 	logger.Debug("Peer added:", id)
	// 	addrInfo := kademliaDHT.FindLocal(id)
	// 	logger.Debug("AddrInfo:", addrInfo)
	// 	logger.Debug("Peers:", host.Peerstore().PeerInfo(id))
	// }

	select {}
}
