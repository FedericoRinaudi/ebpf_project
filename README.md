# **eBPF XDP sniffer**

This program is based on eBPF and XDP.

It allows you to get some information about all packets in a flow (or all of them by setting the FIRST_PACKET_OF_FLOW_ONLY flag to 1).

## **1. Get submodules**

After clone the repo, update the git submodule with following commands:

```sh
git submodule update --init --recursive
```

### **2. Install dependencies**

On Ubuntu, you may run `make install` to install dependencies.

### **3. Build the project**

To build the project, run the following command:

```sh
make build
```

### **4. Run the Project**

You can run the binary with:

```console
sudo src/bootstrap <interface-name>
```

## **Missing features**

- IPV6 extesion headers support
- Fragmentation support
- QUIC recognition
- Multiple TLS messagge in the same packet
- Tails to improve performances

## **Problems**

Still not able to test properly. I run it on the real network and it seems to work, but I need to test it on a controlled environment.

The TLS recognition is not working properly. I'm not able to get the correct information from the packet.

## **License**
I used eunomia-bpf template to create this project.
Eumonia-bpf is licensed under the MIT License. See the **[LICENSE](LICENSE)** file for more information.
