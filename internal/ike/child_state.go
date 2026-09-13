package ike

import (
	"fmt"
	"log/slog"
	"time"
)

// SetChildHandler installs replacement ESP SAs before Run acknowledges a
// peer-initiated rekey, as required by RFC 7296 section 2.8.
func (s *Session) SetChildHandler(fn func(ChildSA) error) {
	s.handlerMu.Lock()
	s.onChild = fn
	s.handlerMu.Unlock()
}

// SetChildRetireHandler removes inbound ESP keys. Replaced SAs are removed
// after the overlap period; an active SA deleted without replacement is
// removed immediately.
func (s *Session) SetChildRetireHandler(fn func(uint32) error) {
	s.handlerMu.Lock()
	s.onRetire = fn
	s.handlerMu.Unlock()
}

// canReplaceChild reports why a replacement could not be installed, so a
// negotiation can refuse before it puts a proposal the peer will act on onto
// the wire.
func (s *Session) canReplaceChild(localSPI uint32) error {
	s.childMu.RLock()
	defer s.childMu.RUnlock()
	return s.canReplaceChildLocked(localSPI)
}

func (s *Session) canReplaceChildLocked(localSPI uint32) error {
	if s.retiring.LocalSPI != 0 {
		return fmt.Errorf("ike: Child SA %08x is still awaiting retirement", s.retiring.LocalSPI)
	}
	if localSPI == s.Child.LocalSPI {
		return fmt.Errorf("ike: Child SA SPI %08x is already active", localSPI)
	}
	for _, retired := range s.retired {
		if localSPI == retired.spi {
			return fmt.Errorf("ike: Child SA SPI %08x is still draining", localSPI)
		}
	}
	return nil
}

func (s *Session) replaceChild(child ChildSA) error {
	s.childMu.Lock()
	defer s.childMu.Unlock()
	if err := s.canReplaceChildLocked(child.LocalSPI); err != nil {
		return err
	}
	if err := s.mux.RegisterESP(child.LocalSPI); err != nil {
		return err
	}
	s.handlerMu.RLock()
	fn := s.onChild
	s.handlerMu.RUnlock()
	if fn != nil {
		if err := fn(child); err != nil {
			s.mux.UnregisterESP(child.LocalSPI)
			return err
		}
	}
	old := s.Child
	s.Child = child
	if old.LocalSPI != 0 {
		s.retiring = old
		// The peer owes a Delete for it, and a peer is free not to send one.
		// Nothing else bounds this, and while it is set every rekey in both
		// directions is refused, so it has a deadline of its own: the SA is
		// retired on the ordinary timer if the Delete never comes.
		s.retiringBy = time.Now().Add(retirementDeadline)
	}
	return nil
}

// retirementDeadline bounds how long a replaced Child SA waits for the peer's
// Delete. RFC 7296 section 2.8 expects one promptly; a peer that never sends it
// would otherwise lock out every later rekey for the life of the session, which
// it can do deliberately by rekeying once and going quiet.
const retirementDeadline = 30 * time.Second

func (s *Session) currentChild() ChildSA {
	s.childMu.RLock()
	defer s.childMu.RUnlock()
	return s.Child
}

func (s *Session) retiringChild() ChildSA {
	s.childMu.RLock()
	defer s.childMu.RUnlock()
	return s.retiring
}

func (s *Session) retireChild(remoteSPI uint32) error {
	s.childMu.Lock()
	defer s.childMu.Unlock()
	retiring := s.retiring
	if retiring.LocalSPI == 0 {
		// Already retired, which is what the peer's own Delete for this SA
		// crossing ours looks like from here: deleteChildren cleared it before
		// our exchange came back. RFC 7296 section 1.4.1 describes the
		// crossing; there is nothing left to do and nothing wrong.
		return nil
	}
	if retiring.RemoteSPI != remoteSPI {
		return fmt.Errorf("ike: no retiring Child SA with remote SPI %08x", remoteSPI)
	}
	if err := s.retireInboundLocked(retiring.LocalSPI, true); err != nil {
		return err
	}
	s.retiring = ChildSA{}
	return nil
}

type childRetirement struct {
	spi       uint32
	expiresAt time.Time
}

// childMu is held across the callback and registration change, so an SPI
// cannot be reused while removal of its previous keys is still in progress.
func (s *Session) retireInboundLocked(spi uint32, replaced bool) error {
	if replaced && s.childRetireDelay > 0 {
		s.retired = append(s.retired, childRetirement{spi, time.Now().Add(s.childRetireDelay)})
		return nil
	}
	s.handlerMu.RLock()
	fn := s.onRetire
	s.handlerMu.RUnlock()
	if fn != nil {
		if err := fn(spi); err != nil {
			return err
		}
	}
	s.mux.UnregisterESP(spi)
	return nil
}

// nextRetirement is when the earliest replaced inbound SA may be dropped, so
// the control loop can wait for it rather than poll for it. The SA waiting for
// the peer's Delete counts too: nothing else would wake the loop to give up on
// a Delete that is not coming.
func (s *Session) nextRetirement() (time.Time, bool) {
	s.childMu.Lock()
	defer s.childMu.Unlock()
	var earliest time.Time
	if len(s.retired) > 0 {
		earliest = s.retired[0].expiresAt
	}
	if s.retiring.LocalSPI != 0 && (earliest.IsZero() || s.retiringBy.Before(earliest)) {
		earliest = s.retiringBy
	}
	return earliest, !earliest.IsZero()
}

func (s *Session) expireRetiredChildren(now time.Time) error {
	s.childMu.Lock()
	defer s.childMu.Unlock()
	// A replaced SA whose Delete never arrived. Retiring it on the timer is
	// what keeps a peer from locking out every later rekey by going quiet;
	// its inbound keys then drain like any other replaced SA.
	if s.retiring.LocalSPI != 0 && !now.Before(s.retiringBy) {
		slog.Warn("ike retiring a replaced Child SA the peer never deleted",
			"spi", s.retiring.LocalSPI, "after", retirementDeadline)
		if err := s.retireInboundLocked(s.retiring.LocalSPI, true); err != nil {
			return fmt.Errorf("ike: retire an undeleted Child SA: %w", err)
		}
		s.retiring = ChildSA{}
	}
	for len(s.retired) > 0 && !now.Before(s.retired[0].expiresAt) {
		if err := s.retireInboundLocked(s.retired[0].spi, false); err != nil {
			return fmt.Errorf("ike: expire retired Child SA: %w", err)
		}
		s.retired = s.retired[1:]
	}
	return nil
}

func (s *Session) forgetChild(child ChildSA) error {
	s.childMu.Lock()
	defer s.childMu.Unlock()
	if s.Child.LocalSPI == 0 {
		return nil
	}
	if s.Child.LocalSPI != child.LocalSPI || s.Child.RemoteSPI != child.RemoteSPI {
		return fmt.Errorf("ike: Child SA changed while handling CHILD_SA_NOT_FOUND")
	}
	if err := s.retireInboundLocked(child.LocalSPI, false); err != nil {
		return err
	}
	s.Child = ChildSA{}
	return nil
}

// deleteChildren closes every locally known Child SA designated by the peer's
// inbound SPIs and returns our paired inbound SPIs for the Delete response
// (RFC 7296 §1.4.1). Unknown SPIs are ignored.
func (s *Session) deleteChildren(remoteSPIs []uint32) ([]uint32, error) {
	s.childMu.Lock()
	defer s.childMu.Unlock()
	localSPIs := make([]uint32, 0, len(remoteSPIs))
	for _, remoteSPI := range remoteSPIs {
		var child *ChildSA
		switch {
		case s.Child.LocalSPI != 0 && s.Child.RemoteSPI == remoteSPI:
			child = &s.Child
		case s.retiring.LocalSPI != 0 && s.retiring.RemoteSPI == remoteSPI:
			child = &s.retiring
		default:
			continue
		}
		if err := s.retireInboundLocked(child.LocalSPI, child == &s.retiring); err != nil {
			return nil, err
		}
		localSPIs = append(localSPIs, child.LocalSPI)
		*child = ChildSA{}
	}
	return localSPIs, nil
}
