# packet-simplemessage
v0.1.11


## Overview

This is a Wireshark Lua dissector for the ROS-Industrial SimpleMessage
protocol. For more information on the protocol, see [simple_message][]. The
current version of the dissector supports only the Groovy version of
SimpleMessage (which is also used in Hydro and Indigo).

![Screenshot of Wireshark dissecting the sample capture](https://github.com/ros-industrial/packet-simplemessage/blob/master/sshot.png)

Packet types dissected:

 * Ping
 * Joint Position
 * Joint Trajectory Point
 * Status
 * Joint Trajectory Point Full
 * Joint Feedback
 * Motoman Motion Control
 * Motoman Motion Reply
 * Motoman Read Single IO
 * Motoman Read Single IO Reply
 * Motoman Write Single IO
 * Motoman Write Single IO Reply
 * Motoman Joint Trajectory Point Full Extended
 * Motoman Joint Feedback Extended

Tested on (but should work on other versions and OS as well):

 * Windows
   * Wireshark 2.0.2 (from [wireshark.org/download][])
 * Linux (Ubuntu)
   * Wireshark 2.0.2 (from [ppa:wireshark-dev/stable][])


## Installation

Make sure the version of Wireshark you have installed was compiled with Lua
support (see [wireshark.org/Lua][]).

If you're not interested in tracking development on the main branch, download
the latest release from the [GitHub Releases][] page and extract the archive
somewhere temporarily (Windows users will likely want to download the zip
archive).

### Linux (per user)

```bash
cd $PACKET_SIMPLEMESSAGE
mkdir -p ~/.local/lib/wireshark/plugins
cp packet-simplemessage.lua ~/.local/lib/wireshark/plugins
```

### Windows (per user)

Open `%USERPROFILE%\AppData\Roaming` (Win7) or `%USERPROFILE%\Application Data`
(WinXP) and open the `Wireshark\plugins` folder (if it doesn't exist, create
it). Now copy `packet-simplemessage.lua` to the `plugins` folder.


## Bugs, feature requests, etc

Please use the [GitHub issue tracker][].



[simple_message]: http://wiki.ros.org/simple_message
[wireshark.org/Lua]: http://wiki.wireshark.org/Lua
[GitHub issue tracker]: https://github.com/ros-industrial/packet-simplemessage/issues
[GitHub Releases]: https://github.com/ros-industrial/packet-simplemessage/releases
[ppa:wireshark-dev/stable]: https://launchpad.net/%7Ewireshark-dev/+archive/ubuntu/stable
[wireshark.org/download]: https://wireshark.org/#download
