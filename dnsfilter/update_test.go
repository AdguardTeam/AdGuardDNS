package dnsfilter

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUpdateDownload(t *testing.T) {
	l := testStartFilterServer()
	defer func() {
		_ = l.Close()
	}()

	u := &updateInfo{
		path: "testfilter.txt",
		url:  fmt.Sprintf("http://127.0.0.1:%d/filter.txt", l.Addr().(*net.TCPAddr).Port),
		ttl:  time.Minute,
	}
	defer func() {
		_ = os.Remove(u.path)
	}()

	err := u.download()
	assert.Nil(t, err)
	assert.FileExists(t, u.path)
}

func testStartFilterServer() net.Listener {
	content := ""
	for i := 0; i < 1000; i++ {
		content = content + "this is test line\n"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/filter.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(content))
	})

	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}

	srv := &http.Server{Handler: mux}

	go func() { _ = srv.Serve(listener) }()
	return listener
}
