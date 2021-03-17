package pacemaker

import (
	"context"
	"math"
	"time"

	"github.com/relab/hotstuff"
	"github.com/relab/hotstuff/config"
	"github.com/relab/hotstuff/consensus"
	"github.com/relab/hotstuff/internal/logging"
)

func init() {
	logger = logging.GetLogger()
}

// FixedLeaderWendyEC uses a fixed leader.
type FixedLeaderWendyEC struct {
	*hotstuff.WendyEC
	leader config.ReplicaID
	notify chan consensus.Event
}

// NewFixedLeaderWendyEC returns a new fixed leader pacemaker
func NewFixedLeaderWendyEC(leaderID config.ReplicaID) *FixedLeaderWendyEC {
	return &FixedLeaderWendyEC{
		leader: leaderID,
	}
}

// Init func
func (p *FixedLeaderWendyEC) Init(wendyEC *hotstuff.WendyEC) {
	p.WendyEC = wendyEC
	// Hack: We receive a channel to HotStuff at this point instead of in Run(),
	// which forces processing of proposals to wait until the pacemaker has started.
	// This avoids the problem of the server handling messages before the Manager
	// has started.
	p.notify = wendyEC.GetEvents()
}

// GetLeader func
func (p *FixedLeaderWendyEC) GetLeader(_ int) config.ReplicaID {
	return p.leader
}

// Run runs the pacemaker which will beat when the previous QC is completed
func (p *FixedLeaderWendyEC) Run(ctx context.Context) {
	if p.Config.ID == p.leader {
		logger.Println("Beat")
		go p.Propose()
	}
	var n consensus.Event
	var ok bool
	for {
		select {
		case n, ok = <-p.notify:
			if !ok {
				return
			}
		case <-ctx.Done():
			return
		}
		switch n.Type {
		case consensus.QCFinish:
			if p.Config.ID == p.leader {
				logger.Println("Beat")
				go p.Propose()
			}
		}
	}
}

// RoundRobinWendyEC change leader in a RR fashion. The amount of commands to be executed before it changes leader can be customized.
type RoundRobinWendyEC struct {
	*hotstuff.WendyEC

	termLength int
	schedule   []config.ReplicaID
	timeout    time.Duration
	notify     chan consensus.Event

	resetTimer  chan struct{} // sending on this channel will reset the timer
	stopTimeout func()        // stops the new-view interrupts
}

// NewRoundRobinWendyEC returns a new round robin pacemaker
func NewRoundRobinWendyEC(termLength int, schedule []config.ReplicaID, timeout time.Duration) *RoundRobinWendyEC {
	return &RoundRobinWendyEC{
		termLength: termLength,
		schedule:   schedule,
		timeout:    timeout,
		resetTimer: make(chan struct{}),
	}
}

// Init func
func (p *RoundRobinWendyEC) Init(wendyEC *hotstuff.WendyEC) {
	p.WendyEC = wendyEC
	// Hack: We receive a channel to HotStuff at this point instead of in Run(),
	// which forces processing of proposals to wait until the pacemaker has started.
	// This avoids the problem of the server handling messages before the Manager
	// has started.
	p.notify = wendyEC.GetEvents()
}

// GetLeader returns the fixed ID of the leader for the view height
func (p *RoundRobinWendyEC) GetLeader(view int) config.ReplicaID {
	term := int(math.Ceil(float64(view) / float64(p.termLength)))
	return p.schedule[term%len(p.schedule)]
}

// Run runs the pacemaker which will beat when the previous QC is completed
func (p *RoundRobinWendyEC) Run(ctx context.Context) {
	// initial beat
	if p.GetLeader(0) == p.Config.ID {
		go p.Propose()
	}

	// get initial notification
	n := <-p.notify

	// make sure that we only beat once per view, and don't beat if bLeaf.Height < vHeight
	// as that would cause a panic
	lastBeat := 0
	beat := func() {
		nextView := p.GetHeight()
		if p.GetLeader(nextView) == p.Config.ID && lastBeat < nextView &&
			nextView >= p.GetVotedHeight() {
			lastBeat = nextView
			go p.Propose()
		}
	}

	// set up new-view interrupt
	stopContext, cancel := context.WithCancel(context.Background())
	p.stopTimeout = cancel
	go p.startNewViewTimeout(stopContext)
	defer p.stopTimeout()

	// handle events from hotstuff
	for {
		switch n.Type {
		case consensus.ReceiveProposal:
			p.resetTimer <- struct{}{}
		case consensus.QCFinish:
			beat()
		case consensus.ReceiveNewView:
			beat()
		}

		var ok bool
		select {
		case n, ok = <-p.notify:
			if !ok {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

// startNewViewTimeout sends a NewView to the leader if triggered by a timer interrupt. Two contexts are used to control
// this function; the stopContext is used to stop the function, and the cancelContext is used to cancel a single timer.
func (p *RoundRobinWendyEC) startNewViewTimeout(stopContext context.Context) {
	for {
		select {
		case <-p.resetTimer:
		case <-stopContext.Done():
			return
		case <-time.After(p.timeout):
			// add a dummy block to the tree representing this round which failed
			logger.Println("NewViewTimeout triggered")
			newHeight := p.GetHeight() + 1
			p.SetLeaf(consensus.CreateLeaf(p.GetLeaf(), nil, nil, newHeight))
			p.SendNewView(p.GetLeader(newHeight))
		}
	}
}
