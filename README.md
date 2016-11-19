# DHCP server
 * use make to translate projekt via provided MAKEFILE

## Compulsory params
  * -p "ip_address/CIDR_mask" is network ip addess representing pool of addresses

NOTE: minimal CIDR mask is /30, masks /31, /32, /0 are not usable, thus they are restricted

## Optional params
  * -e [ip_addresses] are comma separated ip addresses which are not allowed to be leased to hosts
  * -s "static_filename" are static leases, those ip addresses will be available only for specific hosts listed in file
    * static file format example (one record per line)
      * 08:00:27:2d:d0:34 192.168.0.1
      * 08:00:27:2d:d0:24 192.168.0.5

NOTE: -s and -e param are not working together, of you want to restrict ip address
while using -s parameter add ip address you want to restrict with some random mac address

## Usage:
 * ./dserver -p 192.168.0.0/24
 * ./dserver -p 192.168.0.0/24 [-e 192.168.0.1,192.168.0.2]
 * ./dserver -p 192.168.0.0/24 -s static.txt

Author: Martin Krajnak <xkrajn02@stud.fit.vutbr.cz>:
