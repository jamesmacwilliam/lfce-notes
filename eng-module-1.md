 ## Basic Networking

CIDR notation: uses the slash at the end to represent number of bits used for the mask

IE: /24 means first 3 octets, but /25 means also first bit in the last octet (so we start at 128 since the first bit in an octet is worth 2 ^ 8)  reserved private networks:

10.0.0.0/8
172.16.0.0/12
192.168.0.0/16     (notice the remaining bits, larger corps use the 10)

^ these are the super nets, we can always break them down further.

* Use wireshark to track packets

nmtui is useful for setting up connection addresses on CENTOS

exposing private hosts on a network:

NAT - map port to an individual machine (port + IP == socket)  - this used for things like exposing a web server

PAT - map port + ip to many hosts on your network (used for things like web access and is useful because all requests flow through the same access point)

IPV4 vs IPV6
IPV4 says that the last 128 bits are for hosts which leaves about 4 billion hosts
IPV6 has a network portion and a host portion, total length is 128 bits for the address (compared to 32 bit)  Many times we have both an IPV4 and IPV6 address but the iPV4 is used for routing

edit network config directly:
cd /etc/sysconfig/network/network-scripts

then edit ‘ifcg-<Name of Connection>’   something like ifcg-Wired_connection_1
inside that file, we can change the `PREFIX` value which will correspond to the <someIP>/PREFIX value

* restarting networking:
systemctl restart network   (restarts all network interfaces)

restart an individual adapter (IE, if on server0 and want to restart a subnet)
ifdown network_adapter_name   # note: network_adapter_name would be something like `enpos9`
ifup network_adapter_name

open up internet access to subnets:

on server0 (internet connected server) run: firewall-config
switch to the `public` tab and check the `masquerading` checkbox
in the `options` dropdown click `Runtime to permanent`
- this sets up PAT on the subnet hosts (they still need the gateway mask setup so server2 would not yet work but server1 can now access the internet)

ARP (address resolution protocol):
each host has a mac address (48 bits) that uniquely identifies it on a network.  When the ethernet (layer 2) gets a request for a mac address, it sends out a request to all hosts on the network asking who owns the IP address, the owner responds with it’s MAC address, and then the request is sent to the owner.  The IP + MAC address is cached in an ARP cache for fast lookup.

view ARP cache:
sudo ark -a
or:
ip neighbor

arp -d <some ip>   # will delete an ARP cache entry (we can then see the request made in wireshark)
note:  `<some-command> &`  #backgrounds the command


DNS:
map names to IP
A record: is a host
CNAME is an alias

dig <some DNS name> # sends a standard query to a DNS host (will return all the A records for the host)
host <some DNS name> does the same but with a bit less data


IP Packet Structure:

routers determine where packets will go, a host just sends a request to it’s local router.  Routers also are responsible for fragmentation.  (given a MTU - max transmission unit - of 1500) (or 2 networks with different MTUs) the router will break the message up into appropriately sized packets.

IP Packet Header:
32 bits:

first Octet contains:
- the Version (will be 4 for IPV4)
- the Header length (variable depending on header size
TTL (time to live)

1st and 2nd Octet:
UUID for frag. sequence
Protocol (TCP/UDP/ICMP etc)

3rd and 4th Octets
total length

Flags + Fragment Offset

Destination Address


IP Routing decisions:
- check IPTable (is it a local route, then deliver it there)
- not local? send to default route (default gateway)
- TTL (defined in the header, each time the packet passes through a router, the TTL gets decremented - this prevents loops)
- if TTL gets to 0, router responds with an error

traceroute - sends a packet with a 0 TTL, then sends on another one with a TTL of 1, and so on until it finds the whole path through a network

Routing (static vs dynamic)
static: admin defines a path for packets to follow
dynamic: programmatically define path for traffic to follow
VLAN: partitions a layer 2 segment into separate logical LANS (IP networks) requires a router to move data between
* you can use a switch for this, but you might also need to tell your switch which VLAN you’re in, and that’s where VLAN tagging comes in
- Tagged frame is passed to an interface, frame is de-encapsulated as an IP packet and routing decision goes forward like any other packet

can list ip routes via : `ip route`
can add via `ip route add <CIDR notation route> via <regular IP non CIDR> dev <something like enp0s3>`

these routes will get blown away on a sytemctl restart network

persistent routes: switch to /etc/sysconfig/network-scripts
vim route-enp0s3
now add same notation as above, in our case: `192.168.1.1/24 via 192.168.2.1 dev enp0s3` 
after a systemctl restart network, we can now ping 192.168.1.100 (server1) via server 0

can manually add the default gateway of 192.168.2.1 for enp0s3 by editing the `if cfg-<connection name>` file and adding the line:
`GATEWAY=192.168.2.1`  # this will give us internet access once we restart our networking

we can add support for VLAN tagging by adding a new file ifcfg-<network name>.<vlan number>
in our case vim ifcfg-enp0s3.42
similar to a device setup it has: TYPE/BOOTPROTO/NAME/DEVICE/ONBOOT/NETWORK/IPADDR/PREFIX

but also has VLAN=YES

now stop and disable NetworkManager
systemctl disable NetworkManager
systemctl stop NetworkManager

systemctl restart network

# note: we disable networkManager because we did not create the new VLAN through that UI
now if we run `ip -d link show` we can see our new VLAN entry

TCP (transmission control protocol):

- tcp is different than the transports we’ve dealt with so far because it is connection based.  It provides reliable delivery and ensures that each packet is received and it maintains the correct packet order.  It will also error if something goes wrong.
- TCP breaks data up into segments.  Each segment requires a positive ACK, so the sender sends and then recipient sends an ACK.
- this Guarantees the order.
- also provides a checksum, which the receiver runs agains the segment and returns an error if it does not match.

TCP header:
- source port
- dest port
- sequence number
- ack number
- Flags (condition/state)
- Window Size
- Checksum
- options

TCP segment is wrapped in an IP packet and sent to destination, if segment is not ACK, then it is retransmitted, if it is out of order then it is buffered on the receiver.
both the sender and receiver have a connection to each other that can send at the same time (called Full Duplex)

Ports:
1 process per port on an IP, but system can have 2 separate IP’s which would allow for separate web servers each running on port 80
ports = 16 bit value 0 - 65,535
well known ports (system ports) 0-1024 - only accessed by root user
ephemeral ports: 32,768-61000  (used in TCP as source ports)

Connection State (via netstat and ss)

`ss -ltn -4` show us all the listening tcp sockets   (has received q and send q which are queues of packets to send/receive) if we see *:<port> it means it is listening to that port for any IP

`netstat -an | head`   gives us similar information

`ss -t` lists our active connections only  (try an ssh tunnel and notice the new active connection)
note: `ss -t` will also show us the state, so if you ssh to a non-existent host, and the state is SYN_SENT you can see that there is a connection error.

can ACK for multiple packets

congestion control:
congestion window size # of unack segments sent  (sliding window adjusted by receiver, congestion window adjusted by sender)
when we re-transmit a packet (ie: due to not being acknowledged, then we reduce the congestion window so that we don’t saturate the receiver)

UDP (user datagram protocol - send it and forget it)
- used for high perf. networking (might write your own reliability into the packets)
- we also use this for DNS (1 message so no need for connection)
- VOIP - we don’t care about reliability here because timing is everything, dropped packets are just dropped

* you can create large files using `fallocate -l1G <file name>   1 gig file 

* watching window scaling graph on scp request:
window scales up as download progresses making it faster (1 file download is faster than many small ones for this reason, there is a startup cost)

- add policy on device:
`tc qdisc add dev enp0s8 root netem delay 3000ms loss 5%`
`tc qdisc del dev enp0s8 root`

^ useful for testing window size, not sure what else

troubleshooting:

scp something get `Network is unreachable`
- try pinging it  # ping test end to end IP connectivity (layer 3 func.) if it fails we’ve got a layer 3 problem and we should check out routing config
- see if we have a route `ip route` command will show our routes
- if we do, try `ip addr` to examine our connectivity (do we have an IP address, what is the ‘state’ of our connection
- try `arp -a` to see if we have a layer 2 arp cache?
- if not, then we need to go to a lower layer, down to layer 1 # note if the ‘state’ is DOWN in our `ip addr` command, it is a layer 1 problem
- try `arp -a` if no speed/duplex or ‘link detected’ we need to go to our network tab and fix the connectivity.

once we solve our level 1 problem (connecting the network adapter)
- we check level 2 `arp -a`
- if nothing, check `ip route` and determine if we have a route.  What does that route look like, is our network mask correct?
if not fix it in /etc/sysconfig/network-scripts/ifcfg-enp0s3
- then restart the network  `ifdown enp0s3` `ifup enp0s3`

once we’re able to ping:
let’s try scp’ing the file again.
- result: we get no route to host (port 22)

review:
check layer 1
- `ethtool enp0s3` (displays status)
- layer 2 `arp -a`
- layer 3 `ip route` `ip addr` `ping`   IP connectivity
- layer 4 (socket, route + port)  `netstat -an | head` `ss -lnt4` `wireshark`  which ports are listening?

- now lets say that both hosts are listening on port 22 but we’re still getting an issue?
- use wireshark to trace what’s happening  (we see a ‘Host administratively prohibited’ message # firewall issue)
- `firewall-cmd --list -all  # is there a port 22 line in the firewall?  if not, then it is not allowing it through
- firewall-cmd --permanent --zone=public --add-service=ssh





 ## Advanced Networking

what happens on startup:
- BIOS/UEFI looks for bootable device (MBR/GPT) which bootstraps a bootloader (GRUB)
- GRUB eventually loads the Kernel so it keeps track of all Kernels
- once Kernel is running, it runs the init daemon (init pid 1)  - this is what we will focus on

`init` is the first "user" process on the computer (parent of all processes), it is responsible for orderly startup of all other processes

System V (initd was an older init dameon, we now use systemd which relies on sockets to manage the system rather than scripts - more parrel processes)

`lis -la /sbin/init`   init is symbolic link to /lib/systemd/systemd

use systemctl start/stop/status to control services by name

Unit Types: (service/socket/slice (groups units hiearchy)/scope (externally started ie: from terminal)/snapshot/device/mount/swap/automount (on demand filesystem mount)/path/timer (triggers)

- state active/inacive/activating/deactivating
- dependency: before/after/requires/conflicts

unit files - specify behavior of objects:
`man systemd.unit`
locations:
/etc/systemd/system (admin created - take highest precedence)
/run/systemd/system (runtime created)
/usr/lib/systemd/system (installed with packages - lowest precedence)

^ explore the /usr/lib/systemd/system dir for most of our services etc
- use `ls -lat` to find the time that each file was created

naming convention - <name>.<type>  types correspond to the unit types above ^ IE httpd.service
unit file has stanzas:
[Unit] - basic data about the unit
Description=foo bar
After=<space separated list of units that need to run first>
Documentation=man:httpd(8)   # man pages
[Service] - code block
Type=notify #most common
EnvironmentFile=<sets environment variables>
ExecStart=<file to used to start>
ExecReload=<file to run on restart>
ExecStop=..
KillSignal=SIGCONT
PrivateTmp=true # tells systemd to provide privat tmp dir for this process

[Install] - what happens when enable/disable
WantedBy=<space separated list of units> # when enabled, it adds symbolic links when enabled

`man systemd.unit` > you can see desc for each section

`systemctl` with no arguments lists all the units in our system
`systemctl type=sockets` returns all units that are sockets (similar for services/targets etc)

 ## Targets:
replaces runlevels in initd
targets == grouping of units, defines a system state, which units are running

predefined targets: poweroff(0), rescue(1) singleuser mode, `multi-user(2,3,4)` non graphical
graphical(5) reboot(6), emergency, hibernate, suspend

`systemctl list-units --type target` (current state of the system, lists all active targets) - add `--all` to list inactive as well

when we enable a service, it will place a symbolic link in /etc/systemd/system in the <type>.target.wants folder

`systemctl reboot` # reboot is a target so now the system reboots, this works for any target

what state does system boot to? `systemctl get-default` # returns graphical.target, we can change this via `systemctl set-default`

 ## Control Groups (cgroups) - processes are assigned to cgroups organized by service, scope, and slice
- we can assign policies to these such as limiting memory, and assign logging for several sources
- we get these from, kernel/syslog/sd_journal_print/stdout/stderr/audit records (runtime only by default  - can access these logs with `journalctl`)

`systemd-cgls` - gives us the units within a tree (a tree of control groups - the various `.slice` entries)

`systemd-cgtop` shows us the currently running resources

demo: add `MemoryLimit=512M` to /etc/systemd/httpd.service which sets a new policy limit on httpd
to restart, `systemctl daemon reload` `systemctl reload httpd` `systemctl restart httpd`

rather than grepping through `systemctl show httpd`, we can also use 
`systemctl show httpd -p MemoryLimit` if we know the attribute name we'd like to view
`systemctl status httpd` will also give us a paired down list

 ## Getting logs to persist past a reboot for control groups
`sudo mkdir -p /var/log/journal`
`sudo systemctl restart systemd-journald`
now we can run `journalctl` to view the system log (we can jump into /var/log/journal as well but the file there is binary)

`journalctl -f -o verbose`  `-f` is continuous just like `tail`, the -o verbose gives us split out details to make it more greppable

 ## Extended Internet Services Daemon (xinetd)
- shortlived services like TFTP, Telnet

Demo: setup TFTP (trivial FTP)
`sudo yum install xinetd-tftp-server`
`sudo vim /etc/xinetd.d/tftp` (change disable=yes   to no)
`sudo vim /var/lib/tftpboot/file.txt` - add a file to the ftp root
`sudo systemctl restart xinetd`   - we can see what happened with `journalctl -u xinetd`
`sudo firewall-cmd --permanent --add-port=69/udp` # open up the port in firewall
`sudo firewall-cmd --reload` restart it

on the client side (server1)
`sudo yum install tftp` # tftp client
`sudo firewall-cmd --permanent --add-service=tftp-client && firewall-cmd --reload` # open service port and reload
now we can `tftp 192.168.1.1 -c get file.txt` to fetch our file from the ftp server

 ## Monitoring Performance
- core components (CPU/Memory/Disk/Network), Baseline/Benchmarking
- CPU (executes tasks)
 * Symmetric Multi-Process (SMP) - one large memory space
 * Non Uniform Memory Access (NUMA - current model) sections of memory are controlled by a process
   - multiple CPUs access memory within their NUMA Node very quickly (local memory access) but CPUs accessing memory from another NUMA mode is a foreign memory access and moves very slowly (think SWAP memory)

- Scheduling
 * scheduler: schedules threads, default: SCHED_OTHER/SCHED_NORMAL (time sharing)
 * time share scheduling (thread gets to use a CPU for a certain amount of time, and then goes back to the queue) - threads can also pause and go into a waiting state if they rely on another process, and once they are done waiting, they'll get back into the queue
 * pre-emptive, dynamic priority, based on niceness (prioritized queue) the schedulers are also NUMA aware so they will put the threads back onto their NUMA nodes.
 * Process state: Running/Runnable/Sleeping (not in queue)

- CPU what to look for
 * cpu percentages are okay but we need to establish acceptable baseline (obv. we don't want to be too high)
 * length of run queues (means applications are waiting) this is "Load Average"
 * Spikes aren't bad, but if it stays up for a long time, there may be a problem

Demo:

`lscpu` shows us the number of cores, architecture, threads per core, numa nodes (this is the output of the `cat /proc/cpuinfo` file

- generate cpu traffic via `cat /dev/random > /dev/null` repeatedly send random numbers to dev/null

- run `top` and we can see that rngd (the random number generator) is occupying the cpu

Note: `top` shows us the cpu usage, but that doesn't mean it's bad
top also shows us the load averages: the first number is our 1 minute load average, next is our 5 minute load average, then the 15 minute load average (if they are low, then those are acceptable numbers)
under the 'Tasks' heading: we see total number of tasks, how man are running/sleeping/stopped/zombie
we can stop a task with `ctrl + Z` which should then stop the task in `top` use `fg` to start it back up
'Cpus' us (used) ni (nice processes, priority adjusted) id (idle) wa (wait, it will be low for us because it's all random numbers), hi (hardware interrupts) si (software interrupts) st (time stolen from hypervisor)

`w` command: outputs load averages and logging locations
`uptime` gives us uptime + load averages

`dd if=/dev/zero of=test1.img bs=1 count=100000 oflag=sync` (specific writes to file)
    input file    output file  block size  count  oflag (each io will be synchronous)

now run `top` and notice the wait and si (software interrupt) times go up, this means something is slowing the IO in your system (we'll see this behavior with networking problems, or with disk IO saturation (too much IO)

 ## Memory
- physical/virtual  (processes don't have access to physical, only virtual)
- both physical and virtual are broken up into pages which allows us to use memory management tech. called swapping
- 'Swapping' we can move a page from physical memory to the hard disk if it is unused, then we can re-use the physical memory for another application (called a swap out).  This swap out also occurs if the demand for memory is very great in another application (starts with the oldest pages first)  called 'demand paging'
- if a process tries to access the memory that's been moved to disk, we page fault and therefore need to 'swap in' the memory.  Excessive swapping means we have too little memory.  You can adjust the swappiness per process but generally you should leave it alone.

* What to look for:
    - high consumers of space (physical/virtual)
    - excessive swapping
    - file system cache - frequently accessed files and dir are stored in the cache

Demo:
`cat /proc/meminfo | sort`
  - memTotal/MemFree (useful to deep dive into memory layout)
  - `free -m` will give us most of the useful info that we'll need (free space in megabytes)
`dd if=/dev/zero of=test1.img bs=1 count=100000` (same test we used before, but without the sync flag) we get a massive improvement by allowing use of the file system cache (low memory can kill performance if we can't use file system cache)

`top` once in top, press `f` to change sort and then `q` to go back to re-sorted results (ie: sort by memory %)  VIRT + RES should match if we are not paging, otherwise it means we're swapping

`vmstat 1 20` (take a snapshot of our memory 20 times, useful to get an idea of what our memory situation looks like si swap in so swap out, is it all swap in?  probably a memory intensive process)

yum install dstat, `dstat`  # same output as vmstat but formatted a bit nicer

 ## Disk
- sectors (actual storage)
- blocks (logical)
- disk have finite performance:
  * bandwidth: how much data
  * latency: how fast

disk access:
 - sequential: useful for HDD since the head is moving along a disk
 - random: next block is not next to the one before it
 -
Demo:
`yum install iotop`
`dd if=/dev/zero of=test1.img bs=1 oflag=sync`
`iotop` # shows us the user and the disk reads/writes swap and the IO wait
`sudo blockdev --getbsz /dev/sda2` (replace /dev/sda2 with your drive) shows the block size for your drive  (smaller IO's have lower latency but higher IO will consume more bandwidth) optimize for bandwidth then > optimize for latency? smaller IO

when monitoring networks, what to look for:
- saturated interface (do we need more of them)
- bandwidth/latency
- queuing on interfaces
- packet drops

Demo:
`sudo yum install iptraf-ng`
`sudo iptraf-ng` on server 1 -> IP Traffic Monitor -> All Interfaces (all packet transfer)
`ss -t4` shows us the queing, if the queing is high for a small period of time, not an issue, only if it is high for awhile.

 ## Baseline/Benchmarking
- 


next up:
https://app.pluralsight.com/player?course=advanced-network-system-administration-lfce&author=anthony-nocentino&name=advanced-network-system-administration-lfce-m3&clip=3
