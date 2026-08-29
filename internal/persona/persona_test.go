package persona

import "testing"

func valid() Persona {
	return Persona{Version: 1, ID: "p", Host: Host{Hostname: "host", OS: "Debian"}, Files: map[string]File{"/etc/hostname": {Content: "host", Mode: 0444}}, HTTP: HTTP{Routes: []Route{{Path: "/", Methods: []string{"GET"}, Status: 200}}}}
}
func TestValidateRejectsTraversalAndExecutableFiles(t *testing.T) {
	p := valid()
	p.Files["/../etc/shadow"] = File{Mode: 0444}
	if p.Validate() == nil {
		t.Fatal("accepted traversal")
	}
	p = valid()
	p.Files["/tmp/run"] = File{Mode: 0755}
	if p.Validate() == nil {
		t.Fatal("accepted executable persona file")
	}
}
func FuzzValidatePaths(f *testing.F) {
	f.Add("/etc/hostname")
	f.Add("../../etc/passwd")
	f.Fuzz(func(t *testing.T, name string) {
		p := valid()
		p.Files = map[string]File{name: {Mode: 0444}}
		_ = p.Validate()
	})
}
