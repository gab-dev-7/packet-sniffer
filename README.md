# packet-sniffer

A simple packet sniffer written in C that captures TCP and DNS packets and saves them to a `capture.pcap` file.

## Build

To compile the project, run:

```bash
make
```

## Usage

This program requires root privileges to open a raw socket.

```bash
sudo ./sniffer
```

To stop capturing, press `Ctrl+C`. The program will gracefully close the socket and the output file.

## Features

- Captures all packets on the network interface.
- Filters and displays details for TCP packets and DNS requests (port 53).
- Saves captured data to `capture.pcap` which can be opened in Wireshark.