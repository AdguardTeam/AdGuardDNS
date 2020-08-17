// Safe Browsing and Parental Control services

package safeservices

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"

	clog "github.com/coredns/coredns/plugin/pkg/log"
)

// SafeService - safe service object
type SafeService struct {
	// Data for safe-browsing and parental
	// The key is the first 2 bytes of hash value.
	// The value is a byte-array with 30-byte chunks of data.
	// These chunks are sorted alphabetically.
	// map[2_BYTE_HASH_CHUNK] = 30_BYTE_HASH1_CHUNK 30_BYTE_HASH2_CHUNK ...
	data map[uint16][]byte
}

// Return the next non-empty line
func nextLine(reader *bufio.Reader) string {
	for {
		bytes, err := reader.ReadBytes('\n')
		if len(bytes) != 0 {
			if err == nil {
				return string(bytes[:len(bytes)-1])
			}
			return string(bytes)
		}
		if err != nil {
			return ""
		}
	}
}

// Get key for hash map
func getKey(hash2 []byte) uint16 {
	return binary.BigEndian.Uint16(hash2)
}

type hashSort struct {
	data []byte // 30-byte chunks
}

func (hs *hashSort) Len() int {
	return len(hs.data) / 30
}
func (hs *hashSort) Less(i, j int) bool {
	r := bytes.Compare(hs.data[i*30:i*30+30], hs.data[j*30:j*30+30])
	return r < 0
}
func (hs *hashSort) Swap(i, j int) {
	tmp := make([]byte, 30)
	copy(tmp, hs.data[i*30:i*30+30])
	copy(hs.data[i*30:i*30+30], hs.data[j*30:j*30+30])
	copy(hs.data[j*30:j*30+30], tmp)
}

// CreateMap - read input file and fill the hash map
func CreateMap(file string) (*SafeService, int, error) {
	clog.Infof("Initializing: %s", file)
	f, err := os.Open(file)
	if err != nil {
		return nil, 0, err
	}
	reader := bufio.NewReaderSize(f, 4*1024)

	lines := 0
	for {
		ln := nextLine(reader)
		if len(ln) == 0 {
			break
		}
		lines++
	}

	data := make(map[uint16][]byte, lines)

	_, _ = f.Seek(0, 0)
	reader.Reset(f)

	for {
		ln := nextLine(reader)
		if len(ln) == 0 {
			break
		}
		ln = strings.TrimSpace(ln)
		if len(ln) == 0 || ln[0] == '#' {
			continue
		}

		hash := sha256.Sum256([]byte(ln))
		key := getKey(hash[0:2])
		ar, _ := data[key]
		ar = append(ar, hash[2:]...)
		data[key] = ar
	}

	// sort the 30-byte chunks within the map's values
	for k, v := range data {
		hashSorter := hashSort{data: v}
		sort.Sort(&hashSorter)
		data[k] = hashSorter.data
	}

	clog.Infof("Finished initialization: processed %d entries", lines)
	return &SafeService{data: data}, lines, nil
}

// MatchHashes - get the list of hash values matching the input string
func (ss *SafeService) MatchHashes(hashStr string) ([]string, error) {
	result := []string{}

	hashChunks := strings.Split(hashStr, ".")

	for _, chunk := range hashChunks {
		hash2, err := hex.DecodeString(chunk)
		if err != nil {
			return []string{}, err
		}

		if len(hash2) == 4 { // legacy mode
			hash2 = hash2[0:2]
		}

		if len(hash2) != 2 {
			return []string{}, fmt.Errorf("bad hash length: %d", len(hash2))
		}

		hashes, _ := ss.data[getKey(hash2)]
		i := 0
		for i != len(hashes) {
			hash30 := hashes[i : i+30]
			i += 30
			hash := hash2
			hash = append(hash, hash30...)
			result = append(result, hex.EncodeToString(hash))
		}
	}

	clog.Debugf("SB/PC: matched: %s: %v", hashStr, result)
	return result, nil
}

// Search 30-byte data in array of 30-byte chunks
func searchHash(hashes []byte, search []byte) bool {
	start := 0
	end := len(hashes) / 30
	for start != end {
		i := start + (end-start)/2
		r := bytes.Compare(hashes[i*30:i*30+30], search)
		if r == 0 {
			return true
		} else if r > 0 {
			end = i
		} else {
			start = i + 1
		}
	}
	return false
}

// MatchHost - return TRUE if the host is found
func (ss *SafeService) MatchHost(host string) bool {
	hashHost := sha256.Sum256([]byte(host))
	hashes, _ := ss.data[getKey(hashHost[0:2])]

	if searchHash(hashes, hashHost[2:32]) {
		clog.Debugf("SB/PC: matched: %s", host)
		return true
	}

	return false
}
