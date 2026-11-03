package server_auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/francoismichel/ssh3/util/unix_util"
)

func TestIdentityFileReadErrorsFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized_identities")
	if err := os.WriteFile(path, []byte("# test identity\n"+strings.Repeat("x", 128*1024)), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := ParseAuthorizedIdentitiesFile(&unix_util.User{Username: "test-user"}, file); err == nil {
		t.Fatal("identity scanner error was discarded")
	}
}

func TestAuthorizedIdentityFilesAreClosedAfterReading(t *testing.T) {
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("open descriptor counts unavailable")
	}
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, ".ssh3"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh3", "authorized_identities"), []byte("# no identities\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	user := &unix_util.User{Username: "test-user", Dir: home}
	for range 100 {
		if _, err := GetAuthorizedIdentities(user); err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) > len(before)+2 {
		t.Fatalf("authentication leaked descriptors: before=%d, after=%d", len(before), len(after))
	}
}
