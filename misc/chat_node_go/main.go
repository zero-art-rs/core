package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"time"
	"math"

	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
)

var topicNameFlag = flag.String("topicName", "applesauce", "name of topic to join")
const DiscoveryServiceTag = "pubsub-chat-example"

// Construction, which is used to pass paremeters, requiered for testing
type TestHelper struct{
	IsMainKey 			bool
	g_time 				time.Time
	ID					peer.ID

	time_table 			map[string]time.Duration
	ping_sizes			[]int
	averrage_times		[]time.Duration
	record_counter		int
	max_time			time.Duration
	min_time			time.Duration
}

func NewTestHelper(ID peer.ID) *TestHelper {	
	th := TestHelper{
		IsMainKey: false,
		g_time: time.Now(),
		time_table: make(map[string]time.Duration),
		ping_sizes: make([]int, 0),
		averrage_times: make([]time.Duration, 0),
		record_counter: 0,
		max_time: time.Duration(0),
		min_time: time.Duration(1000000), // I assume no one will exide this limmit
		ID: ID,
	}

	return &th
}

// Remove unneceesary information from TestHelper, to execute new tests on
// the same topology.
func ClearTestHelper(th *TestHelper) {
	th.ping_sizes = make([]int, 0)
	th.averrage_times = make([]time.Duration, 0)
	th.record_counter = 0

	th.max_time = time.Duration(0)
	th.min_time = time.Duration(1000000)
}

func main() {
	fmt.Println("Node is running ...")
	flag.Parse()
	ctx := context.Background()

	
	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"))
	if err != nil {
		panic(err)
	}
	
	if err := setupDiscovery(h); err != nil {
		panic(err)
	}
	
	ps, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		panic(err)
	}
	topic, err := ps.Join(*topicNameFlag)
	if err != nil {
		panic(err)
	}

	th := NewTestHelper(h.ID())
	
	go streamConsoleTo(ctx, topic, th, &h)

	sub, err := topic.Subscribe()
	if err != nil {
		panic(err)
	}
	printMessagesFrom(ctx, sub, topic, th)
}

func getPeerInfo(h *host.Host) string {
	// print the node's PeerInfo in multiaddr format
    peerInfo := peer.AddrInfo{
        ID:    (*h).ID(),
        Addrs: (*h).Addrs(),
    }
    addrs, err := peer.AddrInfoToP2pAddrs(&peerInfo)
    if err != nil {
        panic(err)
    }
	return addrs[0].String()
}

func streamConsoleTo(ctx context.Context, topic *pubsub.Topic, th *TestHelper, h *host.Host) {
	reader := bufio.NewReader(os.Stdin)
	for {
		s, err := reader.ReadString('\n')
		if err != nil {
			panic(err)
		}
		if string(s) == "" {
			// Do nothing
		} else if string(s[0]) == "/" { // special logic
			if s == "/set_main\n"{
				th.IsMainKey = true
			}
			if len(s) >= 6 && s[0:6] == "/ping\n" {
				for k := range th.time_table {
					delete(th.time_table, k)
				}
				
				th.g_time = time.Now()
				
				if err := topic.Publish(ctx, []byte("/startping\n")); err != nil {
					fmt.Println("### Republish error:", err)
				}
			}
			if len(s) >= 6 && s[0:6] == "/show\n" {
				i := 1
				acc := time.Duration(0)
				for k, v := range th.time_table { 
					fmt.Printf("[%s] - [%s] - [%d]\n", k, v, i)
					i = i + 1
					acc = acc + v
				}
				fmt.Printf("Averrage time: %s\n", acc / time.Duration(i))
				th.averrage_times = append(th.averrage_times, acc / time.Duration(i))
				th.ping_sizes = append(th.ping_sizes, i - 1)
				th.record_counter += 1

				fmt.Printf("Number of conected peers: %d\n", len((*h).Network().Peers()))
			}
			if len(s) >= 10 && s[0:10] == "/show all\n" {
				average_time := time.Duration(0)
				average_ping_size := 0
				for i := 0; i < th.record_counter; i++ {
					fmt.Printf("%d-th step :: Average time: %s, n_nodes: %d\n", i, th.averrage_times[i], th.ping_sizes[i])
					average_time += th.averrage_times[i]
					average_ping_size += th.ping_sizes[i]
				}
				fmt.Printf("Averrage time: %s\n", average_time / time.Duration(th.record_counter))
				fmt.Printf("Averrage Ping size: %f\n", float64(average_ping_size) / float64(th.record_counter))
			}
			if len(s) >= 6 && s[0:6] == "/peer\n" {
				fmt.Println("libp2p node address:", getPeerInfo(h))
			}
			if len(s) >= 6 && s[0:6] == "/clear tests\n" {
				ClearTestHelper(th)
			}
			if len(s) >= 6 && s[0:6] == "/test\n" {
				for i := 0; i < 150; i++ {
					for k := range th.time_table {
						delete(th.time_table, k)
					}
					
					th.g_time = time.Now()

					if err := topic.Publish(ctx, []byte("/startping\n")); err != nil {
						fmt.Println("### Republish error:", err)
					}

					time.Sleep(6 * time.Second)


					i := 0
					acc := time.Duration(0)
					for _, v := range th.time_table {
						th.min_time = time.Duration(math.Min(float64(th.min_time), float64(v)))
						th.max_time = time.Duration(math.Max(float64(th.max_time), float64(v)))
						acc = acc + v
						i += 1
					}

					th.averrage_times = append(th.averrage_times, acc / time.Duration(i))
					th.ping_sizes = append(th.ping_sizes, i - 1)
					th.record_counter += 1						
				}

				average_time := time.Duration(0)
				average_ping_size := 0
				for i := 0; i < th.record_counter; i++ {
					fmt.Printf("%d-th step :: Average time: %s, n_nodes: %d\n", i, th.averrage_times[i], th.ping_sizes[i])
					average_time += th.averrage_times[i]
					average_ping_size += th.ping_sizes[i]
				}
				fmt.Printf("Averrage time: %s\n", average_time / time.Duration(th.record_counter))
				fmt.Printf("Averrage Ping size: %f\n", float64(average_ping_size) / float64(th.record_counter))
				fmt.Printf("Min time: %s, Max time: %s\n", th.min_time, th.max_time)
				fmt.Printf("number of all conneted peers: %d\n", len((*h).Network().Peers()))
			}
		} else { // Seend typed text
			if err := topic.Publish(ctx, []byte(s)); err != nil {
				fmt.Println("### Publish error:", err)
			}
		}
	}
}

func printMessagesFrom(ctx context.Context, sub *pubsub.Subscription, topic *pubsub.Topic, th *TestHelper) {
	for {
		m, err := sub.Next(ctx)
		if err != nil {
			panic(err)
		}

		m_text := string(m.Message.Data)
		if m_text[:1] == "/" {// special logic
			if len(m_text) >= 11 && m_text[0:11] == "/startping\n" {
				// fmt.Printf("Replay to ping request of %s", string(m.ReceivedFrom))
				// if ID.String() != string(m.ReceivedFrom) {
					if err := topic.Publish(ctx, []byte("/pingreply " + th.ID.String() + "\n")); err != nil {
						fmt.Println("### Republish error:", err)
					}
				// }
			}
			if len(m_text) >= 11 && m_text[0:11] == "/pingreply " {
				ping_node_name := m_text[11:len(m_text) - 1]
				th.time_table[ping_node_name] = time.Since(th.g_time)
				fmt.Printf("%s : [%s]\n", m.ReceivedFrom, ping_node_name)
			}
		} else {// messaging logic
			// if ID.String() != string(m.ReceivedFrom) {
				// (*time_table)[m_text[:len(m_text)-1]] = time.Since(*g_time_ptr)
			// }
			fmt.Printf("%s : [%s]\n", m.ReceivedFrom, m_text[:len(m_text)-1])
		}

	}
}

// discoveryNotifee gets notified when we find a new peer via mDNS discovery
type discoveryNotifee struct {
	h host.Host
}

// HandlePeerFound connects to peers discovered via mDNS. Once they're connected,
// the PubSub system will automatically start interacting with them if they also
// support PubSub.
func (n *discoveryNotifee) HandlePeerFound(pi peer.AddrInfo) {
	fmt.Printf("discovered new peer %s\n", pi.ID)
	err := n.h.Connect(context.Background(), pi)
	if err != nil {
		fmt.Printf("error connecting to peer %s: %s\n", pi.ID, err)
	}
}

func setupDiscovery(h host.Host) error {
	// setup mDNS discovery to find local peers
	s := mdns.NewMdnsService(h, DiscoveryServiceTag, &discoveryNotifee{h: h})
	return s.Start()
}
