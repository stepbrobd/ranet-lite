//go:build darwin && !ios

package kernel

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// The ownership record outlives the process that made it.
//
// Rule one is that only a route this tool recorded writing is ever withdrawn.
// Holding that record in memory alone makes a killed daemon leak one scoped
// default for good, because the next instance has nothing to claim it with and
// claiming it by shape is the one thing the rule forbids. Writing the record
// down changes nothing about the rule and everything about how long it lasts:
// a restart then withdraws what a previous instance of this tool recorded
// writing, which is the same claim rather than a weaker one.
//
// The file lives beside the control socket's lock, in the runtime directory
// this tree already uses for state that says which process owns what, and
// which a `RuntimeDirectory=` unit clears on a clean boot.

// stateMode and stateDirMode match the control socket's lock, which is the
// other thing in that directory saying what this process owns.
const (
	stateMode    = 0o600
	stateDirMode = 0o750
	// maxStateRecords bounds a file nothing else prunes. Two is the working
	// number, one per family; anything approaching this is a node that has
	// crashed on many different interfaces without ever reclaiming, and
	// refusing to grow past it costs one leaked route rather than a file that
	// grows without end.
	maxStateRecords = 32
)

// stateLock is the claim on the state file, held for the life of the process.
// It makes the file this process's to read and rewrite: without it a
// second daemon starting beside a running one reclaims the first's live route,
// which passes every condition because the route is real, resolvable and on
// the primary, and then persists an empty record over it before dying on the
// port.
type stateLock struct{ file *os.File }

func (l *stateLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	// The flock goes with the descriptor, so closing it is the release.
	err := l.file.Close()
	l.file = nil
	return err
}

// lockState takes that claim, or reports that somebody else holds it. An empty
// path locks nothing, which is the in-memory mode a test uses.
func lockState(path string) (*stateLock, error) {
	if path == "" {
		return nil, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), stateDirMode); err != nil {
		return nil, fmt.Errorf("kernel: make the runtime directory for %s: %w", path, err)
	}
	file, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, stateMode)
	if err != nil {
		return nil, fmt.Errorf("kernel: open the lock for %s: %w", path, err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		return nil, fmt.Errorf("kernel: another process holds the record at %s: %w", path, err)
	}
	return &stateLock{file: file}, nil
}

// underlayRecord is one written route as the file holds it. The interface name
// is recorded beside the index because an index is reused across a reboot and
// across a device reordering, and a record matching on the index alone would
// then name a different interface.
type underlayRecord struct {
	Destination string `json:"destination"`
	Index       int    `json:"index"`
	Interface   string `json:"interface"`
	Gateway     string `json:"gateway"`
}

// loadUnderlayState reads the record a previous instance left. A file that is
// absent, unreadable, truncated or not JSON at all yields no records and an
// error the caller reports: starting without a record leaks a route, and
// refusing to start over a state file leaves a node down, so the first is the
// failure to prefer.
func loadUnderlayState(path string) ([]writtenDefault, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("kernel: read %s: %w", path, err)
	}
	var records []underlayRecord
	if err := json.Unmarshal(raw, &records); err != nil {
		return nil, fmt.Errorf("kernel: parse %s: %w", path, err)
	}
	if len(records) > maxStateRecords {
		return nil, fmt.Errorf("kernel: %s holds %d records, over the %d this writes", path, len(records), maxStateRecords)
	}
	out := make([]writtenDefault, 0, len(records))
	for _, record := range records {
		held, err := record.decode()
		if err != nil {
			// One unreadable record does not discard the others, which may
			// each name a route that is still there.
			slog.Warn("kernel is ignoring an underlay record it cannot read", "path", path, "err", err)
			continue
		}
		out = append(out, held)
	}
	return out, nil
}

func (r underlayRecord) decode() (writtenDefault, error) {
	destination, err := netip.ParsePrefix(r.Destination)
	if err != nil {
		return writtenDefault{}, fmt.Errorf("destination %q: %w", r.Destination, err)
	}
	gateway, err := netip.ParseAddr(r.Gateway)
	if err != nil {
		return writtenDefault{}, fmt.Errorf("gateway %q: %w", r.Gateway, err)
	}
	if r.Index <= 0 || r.Interface == "" {
		return writtenDefault{}, fmt.Errorf("interface %q index %d names no link", r.Interface, r.Index)
	}
	held := writtenDefault{destination: destination, index: r.Index, device: r.Interface, gateway: gateway}
	// Round-tripped through the encoder that would have written it, so a
	// record naming something this file could never have produced, a prefix
	// that is not a default above all, is refused before it can reach a
	// delete.
	if _, err := scopedDefaultMessage(unix.RTM_DELETE, held); err != nil {
		return writtenDefault{}, err
	}
	return held, nil
}

// saveUnderlayState replaces the file atomically, so a process dying mid-write
// leaves the previous record rather than a truncated one.
func saveUnderlayState(path string, held []writtenDefault) error {
	if path == "" {
		return nil
	}
	if len(held) > maxStateRecords {
		return fmt.Errorf("kernel: refusing to record %d underlay routes, over the %d this writes", len(held), maxStateRecords)
	}
	records := make([]underlayRecord, 0, len(held))
	for _, one := range held {
		records = append(records, underlayRecord{
			Destination: one.destination.String(),
			Index:       one.index,
			Interface:   one.device,
			Gateway:     one.gateway.String(),
		})
	}
	raw, err := json.Marshal(records)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), stateDirMode); err != nil {
		return fmt.Errorf("kernel: make the runtime directory for %s: %w", path, err)
	}
	temp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("kernel: write %s: %w", path, err)
	}
	defer os.Remove(temp.Name())
	if err := temp.Chmod(stateMode); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(raw); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(temp.Name(), path)
}

// persist writes the current record out. A failure is reported and does not
// stop anything: the process still holds the record in memory and will still
// withdraw what it wrote, and what is lost is only the ability to withdraw it
// after a kill.
func (u *UnderlayDefaults) persist() {
	// Both sets: a record reclaim refused is still a route this tool wrote,
	// and forgetting it would leak it for good. What separates them is that
	// nothing in this process can delete the refused one, not that it is
	// any less ours.
	records := u.sorted()
	for held := range u.refused {
		records = append(records, held)
	}
	slices.SortFunc(records, compareWritten)
	if err := saveUnderlayState(u.statePath, records); err != nil {
		slog.Warn("kernel could not record which underlay routes it wrote",
			"path", u.statePath, "err", err,
			"detail", "a route this process is killed while holding will be left behind")
	}
}

// reclaim withdraws what a previous instance of this tool recorded writing and
// did not live to withdraw. It runs once, before anything is written.
//
// A record is not on its own permission to delete. All of these have to hold,
// and a record failing any of them is kept and reported rather than acted on:
//
//   - the kernel still holds a route at the recorded destination carrying
//     RTF_IFSCOPE, the recorded interface index and the recorded next hop;
//   - the recorded interface name still resolves to the recorded index, so an
//     index reused across a reboot names no route of ours;
//   - that same interface also carries the host's own unscoped default.
//
// The third separates our route from macOS's. macOS writes a scoped
// default for every interface except the one holding the unscoped default, so
// a scoped default on the interface that also holds the unscoped one is a
// shape only this tool produces. Measured on Darwin 27.2.0 by
// TestNoOtherProgramScopesADefaultToThePrimaryInterface, which asserts it on
// whatever machine the suite runs on rather than taking it on trust.
//
// The edge that leaves, stated rather than hidden: it is a snapshot. If the
// host makes another interface primary while our route is in place, ours stops
// being distinguishable, and if that interface later becomes primary again a
// restart could withdraw a scoped default macOS wanted there. The blast radius
// is one route on one interface until the next link event, which macOS answers
// by rewriting it. The alternative, leaving every record forever, leaks on
// every crash.
func (u *UnderlayDefaults) reclaim(records []writtenDefault) {
	if len(records) == 0 {
		return
	}
	rib, err := u.dump()
	if err != nil {
		slog.Warn("kernel is leaving the underlay routes an earlier run recorded, the table would not read back",
			"records", len(records), "err", err)
		u.keep(records)
		return
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		slog.Warn("kernel is leaving the underlay routes an earlier run recorded, the table would not parse",
			"records", len(records), "err", err)
		u.keep(records)
		return
	}
	var kept []writtenDefault
	for _, record := range records {
		switch reason := u.reclaimable(messages, record); reason {
		case "":
			if err := u.withdraw(record); err != nil {
				slog.Warn("kernel could not withdraw an underlay route an earlier run left",
					"destination", record.destination, "interface", record.device, "err", err)
				kept = append(kept, record)
				continue
			}
			slog.Info("kernel withdrew the underlay route an earlier run left behind",
				"destination", record.destination, "interface", record.device,
				"interface_index", record.index, "next_hop", record.gateway)
		case reclaimGone:
			// Nothing of ours is there, so there is nothing to withdraw and
			// nothing to remember.
		default:
			slog.Warn("kernel is leaving an underlay route an earlier run recorded: "+reason,
				"destination", record.destination, "interface", record.device,
				"interface_index", record.index, "next_hop", record.gateway)
			kept = append(kept, record)
		}
	}
	u.keep(kept)
}

// reclaimGone says the recorded route is not in the kernel, which is the one
// outcome that drops a record without withdrawing anything.
const reclaimGone = "the route is already gone"

// reclaimable reports why a record may not be acted on, or empty when every
// condition holds.
func (u *UnderlayDefaults) reclaimable(messages []route.Message, record writtenDefault) string {
	if !heldByKernel(messages, record) {
		return reclaimGone
	}
	index, err := u.lookupDevice(record.device)
	if err != nil {
		return "the interface it names is not present"
	}
	if index != record.index {
		return "the interface it names has a different index now, so the route belongs to another device"
	}
	primary, ok := unscopedDefaultIndex(messages, record.destination)
	if !ok {
		return "the host has no default of that family, so the route cannot be told from one the system wrote"
	}
	if primary != record.index {
		return "the host's own default is on another interface now, so the route cannot be told from one the system wrote"
	}
	return ""
}

// keep holds what reclaim would not act on, apart from the set an ordinary
// withdrawal deletes from.
//
// This is the whole of finding three: reclaim weighed three conditions,
// refused a record, and then handed it to written, from which the next
// withdrawal removed it on the shape check alone, milliseconds later. Every
// condition was worth nothing. Nothing in this process deletes from refused;
// the next start weighs the conditions again.
func (u *UnderlayDefaults) keep(records []writtenDefault) {
	u.refused = make(map[writtenDefault]bool, len(records))
	for _, record := range records {
		u.refused[record] = true
	}
	u.persist()
}

// withdraw sends one delete for a recorded route. Every guard has already run.
func (u *UnderlayDefaults) withdraw(record writtenDefault) error {
	message, err := scopedDefaultMessage(unix.RTM_DELETE, record)
	if err != nil {
		return err
	}
	if err := u.sock.WriteRoute(message); err != nil && !gone(err) {
		return err
	}
	return nil
}

// unscopedDefaultIndex is the interface the host's own default of that family
// leaves by, read from the dump rather than asked for with a lookup: a lookup
// answers with whichever of the routes at that key it prefers, and this has to
// know which one carries no scope at all.
func unscopedDefaultIndex(messages []route.Message, destination netip.Prefix) (int, bool) {
	for _, message := range messages {
		rm, ok := message.(*route.RouteMessage)
		if !ok || rm.Type != unix.RTM_GET || rm.Flags&unix.RTF_IFSCOPE != 0 {
			continue
		}
		if isDefaultKey(rm, destination) {
			return rm.Index, true
		}
	}
	return 0, false
}

// deviceIndex resolves an interface name, which reclaim uses to tell a reused
// index from the device that was recorded.
func deviceIndex(name string) (int, error) {
	device, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return device.Index, nil
}
