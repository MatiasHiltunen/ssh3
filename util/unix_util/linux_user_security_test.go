//go:build linux && !disable_password_auth

package unix_util

import (
	"fmt"
	"sync"
	"testing"
)

func TestPasswordHashingIsSafeForConcurrentRequests(t *testing.T) {
	const setting = "$6$rounds=1000$ssh3-test-salt$"
	expected := make([]string, 8)
	for i := range expected {
		var err error
		expected[i], err = Crypt(fmt.Sprint("test-password-", i), setting)
		if err != nil {
			t.Fatal(err)
		}
	}
	var group sync.WaitGroup
	for i := range expected {
		group.Go(func() {
			for range 8 {
				got, err := Crypt(fmt.Sprint("test-password-", i), setting)
				if err != nil || got != expected[i] {
					t.Errorf("concurrent hash %d returned an incorrect result: %v", i, err)
				}
			}
		})
	}
	group.Wait()
}

func TestPasswordHashingRejectsInvalidSettings(t *testing.T) {
	if _, err := Crypt("test-password", ""); err == nil {
		t.Fatal("invalid password hash setting was accepted")
	}
}
