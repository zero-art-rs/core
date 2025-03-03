# Chat node GO

This is a test ground for the network. It is in early stages of its development.

The purpose is to test the network and especially check if `libp2p` can fulfil our requirements. Also, there are two existing reaches. The first [[1]](#references) is done by creators of `libp2p` and the second [[2]](#references) is done to check if it can be used for Ethereum.

Node in the project is implemented with the usage of `libp2p`. This code is based on examples from the `libp2p` [[3]](#references). Every node have the next paramethers:
* `Mdns` discovery service, to allow peers to discover each other when on the same local network,
* `GossipSub` to make group messaging possible.

One can launch the network of nodes from `chat_node_go` folder using the next command:
```
sh run_tests.sh
```
Currently, it builds new docker image  and run several Docker containers. To interact with the network one can run docker container in interactive mode:
```
docker run -it --rm chat-node-go
```

Running nodes will automaticaly discover new pers. Then one can use console to send messages to other nodes. Also, there are some special commands. They are the text, which starts with slash `/` symbol. They are used only for testing purposes. In future, this behavior should be changed. Currently, there are next commands:
* `/ping` - send a ping request, which is done by sending `/startping` text into the network,
* `/startping` - when received, the node will send it's name, which is a hash of their public key, created automatically.
* `/show` -- show results of one sent ping request. It is a time took for every ID to arrive (time from sending ping minus arrival time divided by two), average arrival time and number of connected peers, which can be smaller than the number of received messages, because of gossipsub nature.
* `/test` - runs several instances of `/ping` tests, and returns the result. It will show average time, average ping size (average number of received messages), min and max delay time.
* `/peer` - returns libp2p node address.
* Some other, which are not necesary for testing.

There where done several tests for different size of network. They wheree done on a machine with 2,2 GHz 6-Core Intel Core i7, 16 GB 2400 MHz DDR4. Results are described below.

|| latency | ping requests delivered |
|----------|-------------|------|
|25 nodes | 28.652397ms | 25 messages |
|50 nodes | 130.252518ms | 48.775 messages |
|75 nodes | 148.373209ms | 67.175 messages |
|100 nodes | 288.23903ms | 88.265 messages |
|125 nodes | 488.655505ms | 103.446667 messages |
|150 nodes | 597.046248ms | 111.566667 messages |
|175 nodes | 912.492405ms | 124.46 messages |

Table shows, that the latency and drop rate are big. There might be several reasons. The first is a DoS atack, which is done by sending the messagee by a big numbe of peeers in the same time. Also there might be a poblem implementation.


## References

[1] https://observablehq.com/@libp2p-workspace/performance-dashboard

[2] https://github.com/whiteblock/gossipsub-testing/tree/master

[3] https://github.com/libp2p/go-libp2p