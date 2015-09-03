readphysmem

(c) fG! - 2015 - reverser@put.as - https://reverse.put.as

A small utility to read and write to Macs physical memory using default AppleHWAccess.kext.

This kext is loaded by default on Mavericks and Yosemite.
It has (finally) been disabled on El Capitan since beta 7 release, since it was a obvious way to bypass and disable the new rootless protection ;-)

Trammell Hudson wrote a similar utility using DirectHW.kext (also blacklisted on El Capitan B7).
Available at https://github.com/osresearch/rwmem.

The same warning as rwmem applies here. Use with caution, it can easily kernel panic your machine both on reads and writes (particularly on devices mapped areas, SMM ram, etc). If you already know PCI BAR addresses you need to use 4 bytes read size instead of default 8. 

It works great to read kernel and other memory, and also BIOS (since it's mapped/shadowed in physical memory). See also https://github.com/gdbinit/diagnostic_service2 for a real world rootkit application.

DirectHW.kext is a bit more powerful since it allows to read port info. AppleHWAccess.kext only implements memory reads and not ports. For example, it can't be used to read PCI configuration.

Have fun,

fG!