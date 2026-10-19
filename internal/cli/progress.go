package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

func stderrIsTTY() bool {
	fi, err := os.Stderr.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func showProgress() bool {
	return !opts.noProgress && stderrIsTTY()
}

// progress draws a single-line transfer indicator on stderr.
// All methods are no-ops when progress output is disabled.
type progress struct {
	label   string
	total   int64 // bytes; <= 0 when unknown
	enabled bool

	mu      sync.Mutex
	done    int64
	last    time.Time
	started time.Time
}

func newProgress(label string, total int64) *progress {
	return &progress{label: label, total: total, enabled: showProgress(), started: time.Now()}
}

// Add records n transferred bytes.
func (p *progress) Add(n int64) {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.done += n
	p.draw(false)
}

// SetPercent records progress as a percentage of total (for vt-go's upload channel).
func (p *progress) SetPercent(pct float32) {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.done = int64(float64(p.total) * float64(pct) / 100)
	p.draw(false)
}

// Status replaces the line with a free-form message (e.g. while polling).
func (p *progress) Status(msg string) {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(os.Stderr, "\r\033[K%s: %s", p.label, msg)
}

// Done clears the progress line.
func (p *progress) Done() {
	if !p.enabled {
		return
	}
	fmt.Fprint(os.Stderr, "\r\033[K")
}

func (p *progress) draw(force bool) {
	now := time.Now()
	if !force && now.Sub(p.last) < 100*time.Millisecond {
		return
	}
	p.last = now
	elapsed := now.Sub(p.started).Seconds()
	rate := ""
	if elapsed > 0 {
		rate = humanSize(int64(float64(p.done)/elapsed)) + "/s"
	}
	if p.total > 0 {
		frac := float64(p.done) / float64(p.total)
		if frac > 1 {
			frac = 1
		}
		const width = 24
		filled := int(frac * width)
		bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
		fmt.Fprintf(os.Stderr, "\r\033[K%s %s %3.0f%% %s/%s %s",
			truncate(p.label, 30), bar, frac*100, humanSize(p.done), humanSize(p.total), rate)
		return
	}
	fmt.Fprintf(os.Stderr, "\r\033[K%s %s %s", truncate(p.label, 30), humanSize(p.done), rate)
}

// writer wraps w so writes are counted toward progress.
func (p *progress) writer(w io.Writer) io.Writer {
	return writerFunc(func(b []byte) (int, error) {
		n, err := w.Write(b)
		p.Add(int64(n))
		return n, err
	})
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }

// uploadChannel returns a channel to hand to vt-go scanners and a function
// that waits until all progress updates have been drawn.
func (p *progress) uploadChannel() (chan<- float32, func()) {
	ch := make(chan float32, 16)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for pct := range ch {
			p.SetPercent(pct)
		}
	}()
	return ch, func() { close(ch); <-done }
}
