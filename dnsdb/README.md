# dnsdb

A simple plugin that records domain names and their IP/CNAME addresses.
This data can then be retrieved by requesting a specified endpoint.

```
dnsdb [ADDR] [PATH]
```

* `[ADDR]` -- local address where you'll be able to retrieve the dnsdb data
* `[PATH]` -- path where we will create the local database

> Every time when you request the dnsdb data, the local database is re-created.
> It is not supposed to be persistent, this is just a cache.

## Example

```
dnsdb 127.0.0.1:9154 /var/tmp/dnsdb.bin
```

* `http://127.0.0.1:9154/csv` -- here you'll be able to retrieve the data.
* `/var/tmp/dnsdb.bin` -- here the local db will be created.