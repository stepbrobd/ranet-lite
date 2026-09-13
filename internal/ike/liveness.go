package ike

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/NickCao/ranet-lite/internal/transport"
)

const (
	defaultDPDInterval = 10 * time.Second
	// dpdRetryDelay is how long a liveness probe that could not be sent at all
	// waits before it is tried again. Short, because nothing is outstanding
	// and the peer may well be there.
	dpdRetryDelay = time.Second
	maxMessageID  = ^uint32(0)
)

var errMessageIDExhausted = errors.New("ike: Message ID space exhausted")

type localRequest struct {
	exchange ExchangeType
	inner    []RawPayload
	context  *ikeContext
	result   chan requestResult
	dpd      bool
}

type requestResult struct {
	inner []RawPayload
	err   error
}

type pendingRequest struct {
	localRequest
	context  *ikeContext
	msgID    uint32
	raw      []byte
	attempts int
	// sent counts transmissions. attempts drives the backoff and stops
	// growing at maxRetransmits, so it cannot also bound the exchange.
	sent     int
	deadline time.Time
}

type rekeySchedule struct {
	name     string
	interval time.Duration
	run      func() error
	timer    *time.Timer
	deadline time.Time
	due      bool
	failures uint
}

type rekeyScheduleResult struct {
	schedule *rekeySchedule
	err      error
}

func findType(payloads []RawPayload, t PayloadType) *RawPayload {
	for i := range payloads {
		if payloads[i].Type == t {
			return &payloads[i]
		}
	}
	return nil
}

func randomRekeyJitter(max time.Duration) (time.Duration, error) {
	if max == 0 {
		return 0, nil
	}
	limit := new(big.Int).Add(big.NewInt(int64(max)), big.NewInt(1))
	v, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return 0, err
	}
	return time.Duration(v.Int64()), nil
}

func (s *Session) rekeyDelay(interval time.Duration) (time.Duration, error) {
	source := s.rekeyJitterSource
	if source == nil {
		source = randomRekeyJitter
	}
	jitter, err := source(s.rekeyJitter)
	if err != nil {
		return 0, fmt.Errorf("ike: generate rekey jitter: %w", err)
	}
	if jitter < 0 || jitter > s.rekeyJitter {
		return 0, fmt.Errorf("ike: invalid rekey jitter %s", jitter)
	}
	delay := interval - s.rekeyMargin - jitter
	if delay <= 0 {
		return 0, fmt.Errorf("ike: nonpositive rekey delay")
	}
	return delay, nil
}

// rekeyRetryDelay backs off exponentially and then spreads the result over the
// upper half of that window. The spread breaks a simultaneous rekey:
// both ends of a collision fail at the same instant and reset the same
// deterministic backoff, so an unjittered retry reproduces the phase
// difference that caused the collision and collides again, forever. RFC 7296
// section 2.8.1 asks for the jitter for that reason.
func (s *Session) rekeyRetryDelay(failures uint) time.Duration {
	delay := s.rekeyRetryInitial
	for failures > 1 {
		if delay >= s.rekeyRetryMax/2 {
			delay = s.rekeyRetryMax
			break
		}
		delay *= 2
		failures--
	}
	source := s.rekeyJitterSource
	if source == nil {
		source = randomRekeyJitter
	}
	// A retry that cannot draw randomness is still better run unjittered.
	jitter, err := source(delay / 2)
	if err != nil || jitter < 0 || jitter > delay/2 {
		return delay
	}
	return delay - jitter
}

func (s *Session) newRekeySchedule(name string, interval time.Duration, run func() error) (*rekeySchedule, error) {
	if interval <= 0 {
		return nil, nil
	}
	delay, err := s.rekeyDelay(interval)
	if err != nil {
		return nil, err
	}
	return &rekeySchedule{name: name, interval: interval, run: run, timer: time.NewTimer(delay), deadline: time.Now().Add(delay)}, nil
}

func (r *rekeySchedule) poll() {
	select {
	case <-r.timer.C:
		r.deadline = time.Time{}
		r.due = true
	default:
	}
}

func (r *rekeySchedule) reset(delay time.Duration) {
	r.timer.Reset(delay)
	r.deadline = time.Now().Add(delay)
}

func nextDueRekey(schedules []*rekeySchedule, running *rekeySchedule) *rekeySchedule {
	if running != nil {
		return nil
	}
	for _, schedule := range schedules {
		if schedule.due {
			schedule.due = false
			return schedule
		}
	}
	return nil
}

// Run is the sole post-handshake IKE receiver. It dispatches authenticated
// peer requests and correlated local responses while also driving DPD.
// dpdInterval is how long a session goes without an authenticated message
// before it probes. A test that has to reach the probe overrides it; zero
// means the default.
func (s *Session) dpdInterval() time.Duration {
	if s.dpdEvery > 0 {
		return s.dpdEvery
	}
	return defaultDPDInterval
}

func (s *Session) Run(ctx context.Context) error {
	var rekeys sync.WaitGroup
	defer func() {
		_ = s.mux.Close() // unblock pending exchanges before joining them
		rekeys.Wait()
	}()
	stop := context.AfterFunc(ctx, func() { _ = s.mux.Close() })
	defer stop()
	s.serving.Store(true)
	defer s.serving.Store(false)
	lastAuthenticated := time.Now()
	s.noteActive()
	if s.rekeyRetryInitial == 0 && s.rekeyRetryMax == 0 {
		s.rekeyRetryInitial = 5 * time.Second
		s.rekeyRetryMax = 5 * time.Minute
	}
	var pending *pendingRequest
	var schedules []*rekeySchedule
	childSchedule, err := s.newRekeySchedule("Child SA", s.childRekeyInterval, s.RekeyChild)
	if err != nil {
		return err
	}
	if childSchedule != nil {
		defer childSchedule.timer.Stop()
		schedules = append(schedules, childSchedule)
	}
	ikeSchedule, err := s.newRekeySchedule("IKE SA", s.ikeRekeyInterval, s.RekeyIKE)
	if err != nil {
		return err
	}
	if ikeSchedule != nil {
		defer ikeSchedule.timer.Stop()
		schedules = append(schedules, ikeSchedule)
	}
	rekeyResult := make(chan rekeyScheduleResult, 1)
	var running *rekeySchedule
	startRekey := func(schedule *rekeySchedule) {
		running = schedule
		slog.Info("ike scheduled rekey starting", "sa", schedule.name)
		rekeys.Go(func() { rekeyResult <- rekeyScheduleResult{schedule, schedule.run()} })
	}
	startDueRekey := func() {
		if schedule := nextDueRekey(schedules, running); schedule != nil {
			startRekey(schedule)
		}
	}
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		if err := s.expireRetiredChildren(time.Now()); err != nil {
			return err
		}
		s.expireRetainedContexts(time.Now())
		select {
		case result := <-rekeyResult:
			if result.err != nil {
				result.schedule.failures++
				delay := s.rekeyRetryDelay(result.schedule.failures)
				result.schedule.reset(delay)
				slog.Warn("ike scheduled rekey failed, retrying", "sa", result.schedule.name, "err", result.err, "retry_in", delay)
				running = nil
				startDueRekey()
				continue
			}
			slog.Info("ike scheduled rekey completed", "sa", result.schedule.name)
			result.schedule.failures = 0
			delay, err := s.rekeyDelay(result.schedule.interval)
			if err != nil {
				return err
			}
			result.schedule.reset(delay)
			running = nil
			startDueRekey()
		default:
		}
		for _, schedule := range schedules {
			schedule.poll()
		}
		startDueRekey()
		if s.trafficSeen.Swap(false) {
			lastAuthenticated = time.Now()
			s.noteActive()
		}
		if pending == nil {
			select {
			case req := <-s.requests:
				var err error
				pending, err = s.startRequest(req)
				if err != nil {
					req.result <- requestResult{err: err}
					if errors.Is(err, errMessageIDExhausted) {
						s.mux.Close()
						return err
					}
				}
			default:
			}
		}

		deadline := lastAuthenticated.Add(s.dpdInterval())
		if pending != nil {
			deadline = pending.deadline
		}
		for _, schedule := range schedules {
			if !schedule.deadline.IsZero() && schedule.deadline.Before(deadline) {
				deadline = schedule.deadline
			}
		}
		// The retirement sweep at the top of the loop has a deadline of its
		// own. It used to be reached by the poll below; now it has to be one
		// of the things the loop actually waits for.
		if retire, ok := s.nextRetirement(); ok && retire.Before(deadline) {
			deadline = retire
		}
		if expiry, ok := s.nextRetainedExpiry(); ok && expiry.Before(deadline) {
			deadline = expiry
		}

		// Everything this loop reacts to is selectable, so it sleeps until one
		// of them happens rather than waking ten times a second to check. That
		// matters on anything running on a battery: one idle session cost 10
		// wakeups per second, and a laptop holds one per peer per family.
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(max(time.Until(deadline), 0))
		// A local request is only accepted while no exchange is outstanding,
		// which a nil channel expresses: IKEv2 permits one at a time.
		var requests <-chan *localRequest
		if pending == nil {
			requests = s.requests
		}
		select {
		case datagram := <-s.mux.IKE():
			if s.dispatch(datagram.Raw, datagram.Endpoint, &pending) {
				lastAuthenticated = time.Now()
				// An answered exchange proves the peer is there just as ESP
				// does, and on a link carrying nothing else, a session kept up
				// by DPD alone, it is the only proof there is.
				s.noteActive()
			}
			continue
		case <-s.mux.Done():
			err := s.mux.Err()
			if pending != nil {
				pending.result <- requestResult{err: err}
			}
			return err
		// These two are handled at the top of the loop; the cases exist so it
		// wakes for them rather than sleeping until the next deadline. Putting
		// the value back cannot block: both channels hold one element, this is
		// their only reader, and each has a single producer that cannot have
		// another value in flight.
		case result := <-rekeyResult:
			rekeyResult <- result
			continue
		case req := <-requests:
			s.requests <- req
			continue
		case <-timer.C:
		}
		// An exchange whose IKE SA has gone can never be answered, and
		// leaving it pending blocks every later local request for the life
		// of the session, since IKEv2 permits one at a time.
		if pending != nil && s.contextRetired(pending.context) {
			pending.result <- requestResult{err: fmt.Errorf("ike: the IKE SA carrying this exchange was replaced")}
			pending = nil
			continue
		}
		if pending != nil && !time.Now().Before(pending.deadline) {
			if pendingRetransmitsExhausted(pending, time.Since(lastAuthenticated) < s.dpdInterval()) {
				s.mux.Close()
				return fmt.Errorf("ike: peer unresponsive after %d attempts", pending.sent)
			}
			// RFC 7296 §2.1 requires retaining and retransmitting the
			// bitwise-identical request until a response arrives or the IKE SA
			// is declared failed. Other authenticated traffic can keep an
			// ordinary exchange alive; a silent peer must still time out.
			// A send that failed locally is a transmission that did not
			// happen, not a peer that has gone. RFC 7296 section 2.4: "an
			// endpoint MUST NOT conclude that the other endpoint has failed
			// based on any routing information (e.g., ICMP messages) ... An
			// endpoint MUST conclude that the other endpoint has failed only
			// when repeated attempts to contact it have gone unanswered for a
			// timeout period." The syscall returns ENETUNREACH while a route
			// is being rewritten, which on a node running this reconciler and
			// a routing daemon is an ordinary moment, and tearing the SA down
			// for it takes every route through the peer with it. The attempt
			// counter declares the peer dead, above.
			if err := s.sendPending(pending); err != nil {
				slog.Warn("ike request retransmission failed, retrying", "exchange", pending.exchange,
					"message_id", pending.msgID, "dpd", pending.dpd, "err", err)
			}
			continue
		}
		// Re-read the traffic edge here rather than relying on the one at
		// the top of the loop. ESP arrives without waking this select, so
		// the timer fires exactly at the deadline with the flag still
		// unconsumed, and a peer sending continuously would be probed every
		// interval forever. RFC 7296 section 2.4 asks for a check only "if
		// no cryptographically protected messages have been received".
		if s.trafficSeen.Swap(false) {
			lastAuthenticated = time.Now()
			s.noteActive()
		}
		if pending == nil && !time.Now().Before(lastAuthenticated.Add(s.dpdInterval())) {
			started, err := s.startRequest(&localRequest{exchange: INFORMATIONAL, result: make(chan requestResult, 1), dpd: true})
			if err != nil {
				// The probe was not sent, which is the retransmission case
				// above rather than a dead peer: startRequest fails on the
				// same local errors, and a pending it did build carries its
				// own attempt budget. Nothing is pending, so the next pass
				// tries again at the next deadline.
				slog.Warn("ike liveness probe not sent, retrying", "err", err)
				lastAuthenticated = time.Now().Add(-s.dpdInterval()).Add(dpdRetryDelay)
			}
			pending = started
		}
		continue
	}
}

// request starts a serialized local exchange through Run. Future Child SA
// rekey support uses this path rather than receiving directly from the mux.
func (s *Session) request(exchange ExchangeType, inner []RawPayload) ([]RawPayload, error) {
	s.requestMu.Lock()
	defer s.requestMu.Unlock()
	return s.requestLocked(exchange, inner)
}

// requestLocked sends a local request while requestMu is held.
func (s *Session) requestLocked(exchange ExchangeType, inner []RawPayload) ([]RawPayload, error) {
	return s.requestOnLocked(s.currentContext(), exchange, inner)
}

func (s *Session) requestOnLocked(context *ikeContext, exchange ExchangeType, inner []RawPayload) ([]RawPayload, error) {
	req := &localRequest{exchange: exchange, inner: inner, context: context, result: make(chan requestResult, 1)}
	select {
	case s.requests <- req:
	case <-s.mux.Done():
		return nil, fmt.Errorf("ike: session closed")
	}
	select {
	case result := <-req.result:
		return result.inner, result.err
	case <-s.mux.Done():
		// Run may have supplied a specific failure immediately before closing.
		select {
		case result := <-req.result:
			return result.inner, result.err
		default:
		}
		return nil, fmt.Errorf("ike: session closed")
	}
}

func (s *Session) startRequest(req *localRequest) (*pendingRequest, error) {
	s.stateMu.RLock()
	context := req.context
	if context == nil {
		context = s.current
	}
	retired := context != s.current
	s.stateMu.RUnlock()
	// A peer rekey may replace the context after a local caller queues work.
	// Do not send a fresh negotiation on an SA the peer is already deleting.
	if req.exchange == CREATE_CHILD_SA && retired {
		return nil, fmt.Errorf("ike: IKE SA changed before Child SA exchange started")
	}
	context.localMIDMu.Lock()
	defer context.localMIDMu.Unlock()
	// Leave the final 32-bit value unused so incrementing the next local ID
	// can never wrap. RFC 7296 §2.2 requires rekeying or closing first.
	if context.nextLocalMID == maxMessageID {
		return nil, errMessageIDExhausted
	}
	msgID := context.nextLocalMID
	flags := uint8(0)
	if !context.responder {
		flags = FlagInitiator
	}
	hdr := Header{SPIInitiator: context.spiI, SPIResponder: context.spiR, ExchangeType: req.exchange, Flags: flags, MessageID: msgID}
	raw, err := context.encrypt(context.localEncryptionKey(), hdr, nil, req.inner)
	if err != nil {
		return nil, err
	}
	pending := &pendingRequest{localRequest: *req, context: context, msgID: msgID, raw: raw}
	if err := s.sendPending(pending); err != nil {
		return nil, err
	}
	// A failed first send did not put a request on the wire, so it must not
	// consume a Message ID. Once sent, this exact request owns the ID until its
	// response arrives (RFC 7296 §2.1-§2.2).
	context.nextLocalMID++
	return pending, nil
}

func (s *Session) sendPending(pending *pendingRequest) error {
	pending.sent++
	nextAttempt := min(pending.attempts+1, maxRetransmits)
	pending.deadline = time.Now().Add(retransmitDelay(nextAttempt))
	pending.attempts = nextAttempt
	if err := s.mux.SendIKE(pending.raw); err != nil {
		return err
	}
	return nil
}

func pendingRetransmitsExhausted(pending *pendingRequest, peerAlive bool) bool {
	if pending.attempts < maxRetransmits {
		return false
	}
	if pending.dpd || !peerAlive {
		return true
	}
	// A peer that keeps authenticated traffic flowing gets more room, because
	// an ordinary exchange can lose out to a busy control loop for a while.
	// Not unlimited room: this exchange holds the one outstanding local
	// request IKEv2 allows, so until it ends there is no rekey, no Delete on
	// teardown and no dead peer detection, and the session reports up the
	// whole time. A peer that answers ESP and never answers IKE, which it can
	// do with RFC 4303 section 2.6 dummy packets alone, would otherwise pin it
	// until the sequence space ran out. RFC 7296 section 2.1 leaves the policy
	// open, "until it either receives a corresponding response or deems the
	// IKE SA to have failed"; this is where it is deemed to have failed.
	return pending.sent >= maxRetransmitsWhileBusy
}

func retransmitDelay(attempt int) time.Duration {
	if attempt <= 1 {
		return requestTimeout
	}
	return requestTimeout << min(attempt-1, maxRetransmits-1)
}

// dispatch returns true only when raw is a fresh authenticated message. Run
// uses that result as evidence of peer liveness; authenticated replays may
// receive a cached response, but must not refresh DPD or migrate the endpoint.
func (s *Session) dispatch(raw []byte, source transport.Endpoint, pending **pendingRequest) bool {
	hdr, err := decodeHeader(raw)
	if err != nil {
		return false
	}
	if hdr.MajorVersion != 2 || hdr.Length != uint32(len(raw)) {
		return false
	}
	ctx := s.contextForHeader(hdr)
	if ctx == nil {
		return false
	}
	var matching *pendingRequest
	if hdr.IsResponse() {
		matching = *pending
		if hdr.IsInitiator() != ctx.responder || matching == nil || matching.context != ctx ||
			hdr.MessageID != matching.msgID || hdr.ExchangeType != matching.exchange {
			return false
		}
	} else if hdr.IsInitiator() != ctx.responder {
		return false
	}
	outer, err := DecodeMessage(raw)
	if err != nil {
		return false
	}
	innerFirst, plaintext, err := decryptMessagePlaintext(ctx.suite, ctx.peerEncryptionKey(), raw, outer)
	if err != nil {
		return false
	}
	if matching == nil {
		s.stateMu.RLock()
		nextPeerMID := ctx.nextPeerMID
		lastPeerResponseID := ctx.lastPeerResponseID
		lastPeerResponse := ctx.lastPeerResponse
		s.stateMu.RUnlock()
		if hdr.MessageID != nextPeerMID {
			if nextPeerMID > 0 && hdr.MessageID == nextPeerMID-1 && lastPeerResponseID == hdr.MessageID {
				if err := s.mux.SendIKETo(lastPeerResponse, source); err != nil {
					s.mux.Close()
				}
			}
			return false
		}
		// We cannot represent the next expected ID after this request. Close
		// before accepting it instead of wrapping the replay window to zero
		// (RFC 7296 §2.2).
		if nextPeerMID == maxMessageID {
			s.mux.Close()
			return true
		}
		// Authentication and a fresh Message ID prove this request came from
		// the live peer rather than being a replay. Only now may it update the
		// endpoint used for future IKE and ESP traffic after NAT port rebinding
		// (RFC 7296 §2.4 and §2.23).
		s.mux.AdoptEndpoint(source)
	}
	inner, err := decodeMessagePlaintext(innerFirst, plaintext)
	if err != nil {
		if matching != nil {
			matching.result <- requestResult{err: fmt.Errorf("ike: malformed authenticated response: %w", err)}
			*pending = nil
		} else if response, responseErr := s.responseNotify(ctx, hdr.MessageID, hdr.ExchangeType, N_INVALID_SYNTAX); responseErr == nil {
			_ = s.mux.SendIKETo(response, source)
		}
		// RFC 7296 §2.21.3 makes authenticated INVALID_SYNTAX fatal to the
		// IKE SA. Responses never generate a further error response.
		s.mux.Close()
		return true
	}
	if matching != nil {
		if err := validateResponseCriticalFlags(outer.Payloads); err != nil {
			matching.result <- requestResult{err: err}
			*pending = nil
			return true
		}
		if err := validateResponseCriticalFlags(inner); err != nil {
			matching.result <- requestResult{err: err}
			*pending = nil
			return true
		}
		matching.result <- requestResult{inner: inner}
		*pending = nil
		return true
	}
	response, err := s.handleRequest(ctx, hdr, inner)
	if err != nil {
		if response != nil {
			_ = s.mux.SendIKETo(response, source)
		}
		s.mux.Close()
		return true
	}
	s.stateMu.Lock()
	ctx.lastPeerResponseID = hdr.MessageID
	ctx.lastPeerResponse = response
	ctx.nextPeerMID++
	s.stateMu.Unlock()
	if err := s.mux.SendIKETo(response, source); err != nil {
		s.mux.Close()
		return true
	}
	return true
}

func (s *Session) contextForHeader(hdr *Header) *ikeContext {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	if hdr.SPIInitiator == s.current.spiI && hdr.SPIResponder == s.current.spiR {
		return s.current
	}
	if s.old != nil && hdr.SPIInitiator == s.old.spiI && hdr.SPIResponder == s.old.spiR {
		return s.old
	}
	if s.collision != nil && hdr.SPIInitiator == s.collision.spiI && hdr.SPIResponder == s.collision.spiR {
		return s.collision
	}
	return nil
}

func (s *Session) handleRequest(ctx *ikeContext, hdr *Header, inner []RawPayload) ([]byte, error) {
	for _, payload := range inner {
		if payload.Critical && !supportedPayloadType(payload.Type) {
			return s.responseNotifyData(ctx, hdr.MessageID, hdr.ExchangeType, N_UNSUPPORTED_CRITICAL_PAYLOAD, []byte{byte(payload.Type)})
		}
	}
	if hdr.ExchangeType == INFORMATIONAL {
		var deletes []Delete
		for _, p := range inner {
			if p.Type != PayloadD {
				continue
			}
			d, err := DecodeDelete(p.Body)
			if err != nil {
				response, responseErr := s.responseNotify(ctx, hdr.MessageID, INFORMATIONAL, N_INVALID_SYNTAX)
				if responseErr != nil {
					return nil, responseErr
				}
				return response, err
			}
			deletes = append(deletes, d)
			if d.Protocol == ProtoIKE {
				response, err := s.response(ctx, hdr.MessageID, INFORMATIONAL, nil)
				if err != nil {
					return nil, err
				}
				removed, releaseSPI := s.removeRetainedContext(ctx)
				if removed || s.adoptCollisionOnPeerDelete(ctx) {
					if !removed || releaseSPI {
						s.mux.UnregisterIKE(ctx.spiI)
					}
					return response, nil
				}
				return response, fmt.Errorf("peer deleted IKE SA")
			}
		}
		var responseSPIs [][]byte
		for _, d := range deletes {
			if d.Protocol != ProtoESP {
				continue
			}
			remoteSPIs := make([]uint32, len(d.SPIs))
			for i, spi := range d.SPIs {
				remoteSPIs[i] = binary.BigEndian.Uint32(spi)
			}
			localSPIs, err := s.deleteChildren(remoteSPIs)
			if err != nil {
				return nil, err
			}
			for _, localSPI := range localSPIs {
				spi := make([]byte, 4)
				binary.BigEndian.PutUint32(spi, localSPI)
				responseSPIs = append(responseSPIs, spi)
			}
		}
		var responsePayloads []RawPayload
		if len(responseSPIs) > 0 {
			responsePayloads = []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: responseSPIs})}}
		}
		return s.response(ctx, hdr.MessageID, INFORMATIONAL, responsePayloads)
	}
	if hdr.ExchangeType == CREATE_CHILD_SA {
		if sa := findType(inner, PayloadSA); sa != nil {
			props, err := DecodeSA(sa.Body)
			if err == nil && len(props) > 0 && props[0].Protocol == ProtoIKE {
				return s.handleIKERekey(ctx, hdr.MessageID, inner)
			}
		}
		return s.handleChildRekey(ctx, hdr.MessageID, inner)
	}
	response, err := s.responseNotify(ctx, hdr.MessageID, hdr.ExchangeType, N_INVALID_SYNTAX)
	if err != nil {
		return nil, err
	}
	return response, fmt.Errorf("ike: unsupported exchange type %d", hdr.ExchangeType)
}

func supportedPayloadType(payloadType PayloadType) bool {
	switch payloadType {
	case PayloadSA, PayloadKE, PayloadIDi, PayloadIDr, PayloadAUTH, PayloadNonce, PayloadN, PayloadD, PayloadTSi, PayloadTSr:
		return true
	default:
		return false
	}
}

func (s *Session) response(ctx *ikeContext, msgID uint32, exchange ExchangeType, inner []RawPayload) ([]byte, error) {
	flags := uint8(FlagResponse)
	if !ctx.responder {
		flags |= FlagInitiator
	}
	hdr := Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: exchange, Flags: flags, MessageID: msgID}
	raw, err := ctx.encrypt(ctx.localEncryptionKey(), hdr, nil, inner)
	if err != nil {
		return nil, fmt.Errorf("ike: build response: %w", err)
	}
	return raw, nil
}

func (ctx *ikeContext) localEncryptionKey() []byte {
	if ctx.responder {
		return ctx.sker
	}
	return ctx.skei
}

func (ctx *ikeContext) peerEncryptionKey() []byte {
	if ctx.responder {
		return ctx.skei
	}
	return ctx.sker
}

func (s *Session) responseNotify(ctx *ikeContext, msgID uint32, exchange ExchangeType, notifyType NotifyType) ([]byte, error) {
	return s.responseNotifyData(ctx, msgID, exchange, notifyType, nil)
}

func (s *Session) responseNotifyData(ctx *ikeContext, msgID uint32, exchange ExchangeType, notifyType NotifyType, data []byte) ([]byte, error) {
	return s.response(ctx, msgID, exchange, []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: notifyType, Data: data})}})
}

func (s *Session) responseNotifySA(ctx *ikeContext, msgID uint32, exchange ExchangeType, notifyType NotifyType, protocol ProtocolID, spi []byte) ([]byte, error) {
	return s.response(ctx, msgID, exchange, []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Protocol: protocol, SPI: spi, Type: notifyType})}})
}

// DeleteIKE tells the peer this IKE SA and every Child SA under it are gone,
// which is the Delete of RFC 7296 section 1.4.1. Without it the far end keeps
// its half, keeps sending ESP into an SPI we no longer accept, and only
// notices when its own dead peer detection expires, which is over a minute.
//
// It is best effort by construction: the caller is tearing the session down
// either way, so a peer that has already vanished costs only the exchange's
// own retransmission budget, and the caller bounds that.
func (s *Session) DeleteIKE() error {
	payloads := []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoIKE})}}
	if s.serving.Load() {
		_, err := s.request(INFORMATIONAL, payloads)
		return err
	}
	// Nothing is draining the request queue, so the exchange has to go out
	// directly. This is the common case for a session resolved away the moment
	// it was established: it is closed before it is ever served, and routing
	// the Delete through a loop that will never run would send nothing at all.
	return s.sendUnansweredRequest(payloads)
}

// sendUnansweredRequest transmits one encrypted request and does not wait for
// the response.
func (s *Session) sendUnansweredRequest(inner []RawPayload) error {
	s.requestMu.Lock()
	defer s.requestMu.Unlock()
	ctx := s.currentContext()
	ctx.localMIDMu.Lock()
	defer ctx.localMIDMu.Unlock()
	flags := uint8(0)
	if !ctx.responder {
		flags = FlagInitiator
	}
	header := Header{
		SPIInitiator: ctx.spiI,
		SPIResponder: ctx.spiR,
		ExchangeType: INFORMATIONAL,
		Flags:        flags,
		MessageID:    ctx.nextLocalMID,
	}
	request, err := ctx.encrypt(ctx.localEncryptionKey(), header, nil, inner)
	if err != nil {
		return fmt.Errorf("ike: build IKE Delete: %w", err)
	}
	ctx.nextLocalMID++
	return s.mux.SendIKE(request)
}
