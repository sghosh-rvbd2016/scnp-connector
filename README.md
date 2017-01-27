SteelCentral NetProfiler Connector
============================

### Overview

A simple tool for exporting visibility data (ie NetFlow) securely to NetProfiler products using the MNMP protocol.

See [SharePoint Document](https://rvbdtech.sharepoint.com/teams/eng/sc/yaris/_layouts/15/guestaccess.aspx?guestaccesstoken=1zVHlpC8jSGXJSmeLQMHUoRNWPMlGxs8xNOqZuiIh9s=&docid=2_160b407b4d81e474ea409b307c8ee2170&rev=1)

### Building

> make

### Installing

> make install

### Installed File Locations

Binaries: /opt/npm/bin/flowlogging/scnp-connector
SSL credentials: /etc/npm/flowlogging/ssl

### Program Options

> Usage: /opt/npm/bin/flowlogging/scnp-connector --id --netprofiler <hostname> [OPTIONS]
>
> Required Arguments:
>
>    --id <integer>		Set MNMP ID for this node.
>    --netprofiler <hostname|IP>	NetProfiler to connect to.
>
>Optional Arguments:
>
>   --certificate <file>         SSL certificate to use for MNMP.
>   --debug[,2,3]                Log debug messages, level 2/3 optional.
>   --help                       Show this message.
>   --netflow-addr               IPv4 address to accept Netflow on.
>   --netflow-port               UDP port to accept Netflow on.
>   --netflow-relay              Connect and relay NetFlow records to NetProfiler.
>   --no-compression             Do not compress flow messages.
>   --syslog			Log messages to syslogd.
>   --trusted-certs <dir>        Path to directory containing trusted certificates.
>   --quiet			Only log errors.

### Example Usage

The below example will listen for NetFlow on 0.0.0.0:2055 on the localhost and relay
the NetFlow records to the NetProfiler at 10.10.10.10 compressed with LZ4 and encrypted with SSL.
The output will be logged to syslog in this example.

**NOTE:** You must specify a unique MNMP for this instance, which should be a 64-bit unsigned integer,
the machines primary MAC address plus an offset will be ideal.

>
> /opt/npm/bin/flowlogging/scnp-connector --id 4141216738852864 --netprofiler 10.10.10.10 --netflow-relay --netflow-addr 0.0.0.0 --netflow-port 2055 --syslog
>

### Example Output

> Jan 22 12:11:27 netprofiler scnp-connector[20151]: Established TLSv1.2 connection (4->10.10.10.10:41017): cipher name: AES256-SHA version: TLSv1/SSLv3 bits: 256
> Jan 22 12:11:27 netprofiler scnp-connector[20151]: Succesfully bound to 0.0.0.0:2055
> Jan 22 12:11:27 netprofiler scnp-connector[20151]: Welcome message from cascade-express (4141216738836481) type mazu
> Jan 22 12:12:00 netprofiler scnp-connector[20151]: slice 1485547860: relayed 764 datagrams (input 764, maxq in 22/1000 out 2/1000)
> Jan 22 12:13:00 netprofiler scnp-connector[20151]: slice 1485547920: relayed 1414 datagrams (input 1414, maxq in 25/1000 out 3/1000)
> Jan 22 12:14:00 netprofiler scnp-connector[20151]: slice 1485547980: relayed 1240 datagrams (input 1240, maxq in 30/1000 out 3/1000)
> Jan 22 12:15:00 netprofiler scnp-connector[20151]: slice 1485548040: relayed 1316 datagrams (input 1316, maxq in 21/1000 out 3/1000)
> Jan 22 12:16:00 netprofiler scnp-connector[20151]: slice 1485548100: relayed 1403 datagrams (input 1403, maxq in 39/1000 out 3/1000)
> Jan 22 12:17:00 netprofiler scnp-connector[20151]: slice 1485548160: relayed 1540 datagrams (input 1540, maxq in 31/1000 out 3/1000)
> Jan 22 12:18:00 netprofiler scnp-connector[20151]: slice 1485548220: relayed 1543 datagrams (input 1543, maxq in 32/1000 out 3/1000)
