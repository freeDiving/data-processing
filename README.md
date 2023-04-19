# Exp1 Data Process

## TODO

- [x] Extract app logs with format
    - [x] filter lines with phase mark
    - [x] extract timestamp
    - [x] extract 1a touch screen event
    - [x] extract create stroke event (id, timestamp)
    - [x] order events by timestamp ASC
- [x] Extract pcap data with format by filter
- [x] Merge data into csv
- [x] Plot data into timeline
- [ ] Calculate phases
- [ ] Plot data into formal plotting

## TimeLine

### For One Data Packet

- [1a]: t2 - t1
    - t1: T(touch screen event on host)
    - t2: T(first data pkt sent by host)
- [1b]: t3 - t2
    - t3: T(the corresponding ack pkt received from cloud)
- [1c]: t4 - t3
    - t4: T(the data pkt received from cloud by host)
- [2x]: t5 - t4
- [2a]: t6 - t5
    - t5: T(the data pkt received from cloud by resolver)
    - t6: T(the corresponding ack pkt sent by resolver)
- [2d]: t7 - t6
    - t7: T(the rendering finished by resolver)