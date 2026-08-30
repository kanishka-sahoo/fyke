package ops

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const nftRules = `#!/usr/sbin/nft -f
table inet fyke {
  chain sensor_egress {
    type filter hook forward priority filter; policy accept;
    ct state established,related accept
    iifname "fyke-sensors" oifname "fyke-control" tcp dport 9443 accept
    iifname "fyke-sensors" counter drop
  }
}
`

func FirewallApply(dataDir string) error {
	file := filepath.Join(dataDir, "fyke.nft")
	if e := os.WriteFile(file, []byte(nftRules), 0600); e != nil {
		return e
	}
	// Replacing Fyke's own table makes repeated explicit applications safe.
	_ = exec.Command("nft", "delete", "table", "inet", "fyke").Run()
	cmd := exec.Command("nft", "-f", file)
	out, e := cmd.CombinedOutput()
	if e != nil {
		return fmt.Errorf("nft apply: %w: %s", e, out)
	}
	return nil
}
func FirewallRules() string { return nftRules }
