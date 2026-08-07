package patch

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

const maxFixSetItems = 50

// DependencyRule is one static rule: when a main fix (asset_name/fix_type/
// fix_value) is generated, add the dependency fix to the same task. A rule
// only applies when the dependency asset is installed on the agent.
type DependencyRule struct {
	ID                 int64  `json:"id"`
	AssetName          string `json:"asset_name"`
	FixType            string `json:"fix_type"`
	FixValue           string `json:"fix_value,omitempty"`
	DependencyAsset    string `json:"dependency_asset"`
	DependencyFixType  string `json:"dependency_fix_type"`
	DependencyFixValue string `json:"dependency_fix_value,omitempty"`
	Required           bool   `json:"required"`
	Reason             string `json:"reason,omitempty"`
	SourceRef          string `json:"source_ref,omitempty"`
	Enabled            bool   `json:"enabled"`
}

// FixDependency is the reporting view of one rule applied to a fix set.
type FixDependency struct {
	AssetName string `json:"asset_name"`
	FixType   string `json:"fix_type"`
	FixValue  string `json:"fix_value,omitempty"`
	Required  bool   `json:"required"`
	Reason    string `json:"reason,omitempty"`
	SourceRef string `json:"source_ref,omitempty"`
}

// FixSetItem is one command-producing element of a patch closure. The first
// item is the main fix; the rest are required dependencies.
type FixSetItem struct {
	AssetName    string          `json:"asset_name"`
	FixType      string          `json:"fix_type"`
	FixValue     string          `json:"fix_value"`
	Action       string          `json:"action"`
	PatchURL     string          `json:"patch_url,omitempty"`
	PatchSHA256  string          `json:"patch_sha256,omitempty"`
	CVEIDs       []string        `json:"cve_ids,omitempty"`
	Dependencies []FixDependency `json:"dependencies,omitempty"`
}

func ruleMatches(r DependencyRule, item FixSetItem) bool {
	if !r.Enabled || !r.Required {
		return false
	}
	if r.AssetName != item.AssetName || r.FixType != item.FixType {
		return false
	}
	return r.FixValue == "" || r.FixValue == item.FixValue
}

func fixSetItemKey(it FixSetItem) string {
	return it.AssetName + "\x00" + it.FixType + "\x00" + it.FixValue
}

func actionForFixType(fixType string) string {
	if fixType == "kb" {
		return "install_patch"
	}
	return "upgrade_package"
}

// ExpandFixSet builds the closure of a main fix: the main item plus every
// required dependency whose rule matches and whose asset is installed.
// Dependency-of-dependency expansion is recursive with a bounded frontier,
// and self/back references are rejected.
func ExpandFixSet(main FixSetItem, rules []DependencyRule, installed map[string]bool) ([]FixSetItem, error) {
	items := []FixSetItem{main}
	seen := map[string]bool{fixSetItemKey(main): true}
	queue := []FixSetItem{main}
	applied := map[string]FixDependency{}
	for len(queue) > 0 {
		if len(items) > maxFixSetItems {
			return nil, errors.New("fix set expansion exceeded 50 items")
		}
		cur := queue[0]
		queue = queue[1:]
		for _, r := range rules {
			if !ruleMatches(r, cur) {
				continue
			}
			if !installed[r.DependencyAsset] {
				continue
			}
			dep := FixSetItem{
				AssetName:   r.DependencyAsset,
				FixType:     r.DependencyFixType,
				FixValue:    r.DependencyFixValue,
				Action:      actionForFixType(r.DependencyFixType),
				PatchURL:    "",
				PatchSHA256: "",
			}
			key := fixSetItemKey(dep)
			if seen[key] || dep.AssetName == main.AssetName {
				continue
			}
			seen[key] = true
			items = append(items, dep)
			queue = append(queue, dep)
			applied[key] = FixDependency{
				AssetName: r.DependencyAsset,
				FixType:   r.DependencyFixType,
				FixValue:  r.DependencyFixValue,
				Required:  r.Required,
				Reason:    r.Reason,
				SourceRef: r.SourceRef,
			}
		}
	}

	deps := make([]FixDependency, 0, len(applied))
	for _, d := range applied {
		deps = append(deps, d)
	}
	sort.Slice(deps, func(i, j int) bool {
		return deps[i].AssetName < deps[j].AssetName
	})
	items[0].Dependencies = deps

	sort.Slice(items, func(i, j int) bool {
		if items[i].AssetName != items[j].AssetName {
			return items[i].AssetName < items[j].AssetName
		}
		if items[i].FixType != items[j].FixType {
			return items[i].FixType < items[j].FixType
		}
		return items[i].FixValue < items[j].FixValue
	})
	return items, nil
}

// HashFixSet returns a stable SHA256 over the canonical fix set JSON. The
// main item must stay first so the hash changes when the main fix changes,
// even if the dependency list is empty.
func HashFixSet(items []FixSetItem) string {
	if len(items) == 0 {
		items = []FixSetItem{}
	}
	canonical := make([]FixSetItem, 0, len(items))
	if len(items) > 0 {
		main := items[0]
		main.CVEIDs = sortedCopy(main.CVEIDs)
		main.Dependencies = nil
		canonical = append(canonical, main)
		rest := append([]FixSetItem{}, items[1:]...)
		sort.Slice(rest, func(i, j int) bool {
			if rest[i].AssetName != rest[j].AssetName {
				return rest[i].AssetName < rest[j].AssetName
			}
			if rest[i].FixType != rest[j].FixType {
				return rest[i].FixType < rest[j].FixType
			}
			return rest[i].FixValue < rest[j].FixValue
		})
		canonical = append(canonical, rest...)
	}
	raw, _ := json.Marshal(canonical)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func sortedCopy(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}

// BuildCommandsForFixSet builds one aggregated command for a fix set. Every
// item maps to its own argv list; the set is deployable only when every
// item is deployable.
func BuildCommandsForFixSet(cfg *Config, items []FixSetItem, agentOS, agentVersion string) (Command, error) {
	if len(items) == 0 {
		return Command{Display: "no automated remediation"}, nil
	}
	manager := packageManagerForAgent(agentOS, agentVersion)
	var all [][]string
	var displays []string
	deployable := true
	for _, it := range items {
		c, err := buildCommand(cfg, manager, it.FixType, it.FixValue,
			it.AssetName, it.PatchURL, it.PatchSHA256)
		if err != nil {
			return Command{}, err
		}
		if !c.Deployable {
			deployable = false
		}
		all = append(all, c.ArgvLists...)
		displays = append(displays, c.Display)
	}
	return Command{
		Display:    strings.Join(displays, " && "),
		ArgvLists:  all,
		Deployable: deployable,
	}, nil
}
