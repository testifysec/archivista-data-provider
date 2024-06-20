package utils

import (
	"context"
	"log"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Watcher is an opinionated fsnotify.Watcher that is designed to
// watch Kubernetes config maps and perform actions on change.
type Watcher struct {
	actions []func() error
	notify  chan struct{}
}

// Notify manually runs all actions in a watcher
func (w *Watcher) Notify() {
	go func(w *Watcher) {
		w.notify <- struct{}{}
	}(w)
}

func NewWatcher(ctx context.Context, filePath string, actions ...func() error) (*Watcher, error) {
	w := &Watcher{
		actions: actions,
		notify:  make(chan struct{}),
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	err = watcher.Add(filePath)
	if err != nil {
		return nil, err
	}

	go func(w *Watcher, watcher *fsnotify.Watcher) {
		// only perform actions every 5 seconds at most
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		// we only really care about the last fsnotify event, as we are going to attempt to perform actions
		// every 5 seconds. If there were 2 writes in that time we don't really mind.
		var lastEvent *fsnotify.Event
		runAll := func(actions ...func() error) []error {
			var allErrors []error
			for _, a := range w.actions {
				if err := a(); err != nil {
					allErrors = append(allErrors, err)
				}
			}
			return allErrors
		}
		for {
			select {
			case <-w.notify:
				allErrors := runAll(w.actions...)
				for _, e := range allErrors {
					log.Printf("error while reloading config (%s)", e.Error())
				}
			case <-t.C:
				if lastEvent == nil {
					continue
				}
				allErrors := runAll(w.actions...)
				for _, e := range allErrors {
					log.Printf("error while reloading file %s (%s)", lastEvent.Name, e.Error())
				}
				// if no errors, clear the last event.
				if len(allErrors) == 0 {
					lastEvent = nil
				}
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				// When a config map is updated, behind the scenes Kubernetes creates
				// a new directory with the new contents, then replaces the symlink to point
				// to the new config map, then deletes the old one. In this case, we get a delete
				// event rather than a write event.
				if event.Op == fsnotify.Remove {
					// Only error here would be attempting to remove a non-existent watch
					_ = watcher.Remove(event.Name)
					err := watcher.Add(event.Name)
					if err != nil {
						log.Fatalf("file %s change detected, but could not re-watch the file: %s", event.Name, err.Error())
					}
					lastEvent = &event
				}
				// However, people might not be using a config map after all
				if event.Op == fsnotify.Write || event.Op == fsnotify.Create {
					lastEvent = &event
				}
			case <-ctx.Done():
				watcher.Close()
				return
			}
		}
	}(w, watcher)
	return w, nil
}
