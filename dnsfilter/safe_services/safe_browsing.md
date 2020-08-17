# Parental Control and SafeBrowsing

## Initialization

Input data is a file with the list of host names that must be blocked (both PC & SB services have their own filter file):

	badsite1
	badsite2
	...

When PC/SB services are initializing they:

* get the total number of lines in file and create a hash map
* read the file line by line
* get SHA256 hash sum of the host name
* add the sum value into the hash map as shown below

Suppose that there are 2 host names with similar hash sums:

	01abcdef1234...
	01abcdef0987...

Add these hashes to the hash map like so that:

* the key equals to bytes [0..1] of each hash sum
* the value equals to an array of bytes [2..31] of each hash sum

e.g.:

	"01ab" -> []{
		"cdef1234...",
		"cdef0987..."
	}

And for a faster search we sort the hashes:

	"01ab" -> []{
		"cdef0987..."
		"cdef1234...",
	}

## DNS messages

To check if the host is blocked, a client sends a TXT record with the Name field equal to the hash value of the host name.

	DNS Question:
	NAME=[0x04 "01ab" 0x04 "2345" 0x02 "sb" 0x03 "dns" 0x07 "adguard" 0x03 "com" 0x00]
	TYPE=TXT
	CLASS=IN

Legacy mode is also supported where the length of 1 hash is 8 characters, not 4.

For the server to distinguish between SB or PC requests, the Name field in the question has either "pc" or "sb" suffix.  For example, the Name in the previous request, only now for PC service, will look like this:

	NAME=[0x04 "01ab" 0x04 "2345" 0x02 "pc" 0x03 "dns" 0x07 "adguard" 0x03 "com" 0x00]

In this request a client wants to check 2 domains with the hash sums starting with "01ab" and "2345".

The response to this request is the list of SHA256 hash values that start with "01ab" and "2345".

	DNS Answers:
	[0]:
	NAME=[0x04 "01ab" 0x04 "2345" 0x02 "sb" ...]
	TYPE=TXT
	CLASS=IN
	TTL=...
	LENGTH=...
	DATA=["01abcdef1234...", "01abcdef0987...", "23456789abcd..." ]

Upon receiving the response the client compares each hash value with its target host.
If the hash values match, it means that this host is blocked by PC/SB services.

Note that since neither the client nor the server trasmits the full host name along with its hash sum, there may be a chance of a hash collision and so the host which is not in the blocklist will be treated as blocked.
