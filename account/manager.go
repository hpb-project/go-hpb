// Copyright 2018 The go-hpb Authors
// This file is part of the go-hpb.
//
// The go-hpb is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-hpb is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-hpb. If not, see <http://www.gnu.org/licenses/>.

package accounts

import (
	"sort"
	"sync"

	"sync/atomic"
	"github.com/hpb-project/go-hpb/event/sub"
)

var INSTANCE = atomic.Value{}

// Manager is an overarching account manager that can communicate with various
// backends for signing transactions.
type Manager struct {
	store   Backend            // Index of backends currently registered
	updater sub.Subscription // Wallet update subscriptions for all backends
	updates chan WalletEvent   // Subscription sink for backend wallet changes
	wallets []Wallet           // Cache of all wallets from all registered backends

	feed sub.Feed // Wallet feed notifying of arrivals/departures

	quit chan chan error
	lock sync.RWMutex
}

// NewManager creates a generic account manager to sign transaction via various
// supported backends.
func NewManager(back Backend) *Manager {
	if INSTANCE.Load() != nil {
		return GetManager()
	}
	// Subscribe to wallet notifications from all backends
	updates := make(chan WalletEvent, 4)

	sub := back.Subscribe(updates)

	// Assemble the account manager and return
	am := &Manager{
		store:   back,
		updater: sub,
		updates: updates,
		wallets: back.Wallets(),
		quit:    make(chan chan error),
	}
	go am.update()
	INSTANCE.Store(am)
	return am
}

// Close terminates the account manager's internal notification processes.
func (am *Manager) Close() error {
	errc := make(chan error)
	am.quit <- errc
	return <-errc
}

// update is the wallet event loop listening for notifications from the backends
// and updating the cache of wallets.
func (am *Manager) update() {
	// Close all subscriptions when the manager terminates
	defer func() {
		am.lock.Lock()
		am.updater.Unsubscribe()
		am.updater = nil
		am.lock.Unlock()
	}()

	// Loop until termination
	for {
		select {
		case event := <-am.updates:
			// Wallet event arrived, update local cache
			am.lock.Lock()

			switch event.Kind {
			case WalletArrived:
				am.wallets = merge(am.wallets, event.Wallet)
			case WalletDropped:
				am.wallets = drop(am.wallets, event.Wallet)
			}
			am.lock.Unlock()

			// Notify any listeners of the event
			am.feed.Send(event)

		case errc := <-am.quit:
			// Manager terminating, return
			errc <- nil
			return
		}
	}
}

// Backends retrieves the backend(s) with the given type from the account manager.
func (am *Manager) KeyStore() Backend {
	return am.store
}

// Wallets returns all signer accounts registered under this account manager.
func (am *Manager) Wallets() []Wallet {
	am.lock.RLock()
	defer am.lock.RUnlock()

	cpy := make([]Wallet, len(am.wallets))
	copy(cpy, am.wallets)
	return cpy
}

// Wallet retrieves the wallet associated with a particular URL.
func (am *Manager) Wallet(url string) (Wallet, error) {
	am.lock.RLock()
	defer am.lock.RUnlock()

	parsed, err := parseURL(url)
	if err != nil {
		return nil, err
	}
	for _, wallet := range am.Wallets() {
		if wallet.URL() == parsed {
			return wallet, nil
		}
	}
	return nil, ErrUnknownWallet
}

// Find attempts to locate the wallet corresponding to a specific account. Since
// accounts can be dynamically added to and removed from wallets, this method has
// a linear runtime in the number of wallets.
func (am *Manager) Find(account Account) (Wallet, error) {
	am.lock.RLock()
	defer am.lock.RUnlock()

	for _, wallet := range am.wallets {
		if wallet.Contains(account) {
			return wallet, nil
		}
	}
	return nil, ErrUnknownAccount
}

// Subscribe creates an async subscription to receive notifications when the
// manager detects the arrival or departure of a wallet from any of its backends.
func (am *Manager) Subscribe(sink chan<- WalletEvent) sub.Subscription {
	return am.feed.Subscribe(sink)
}

// merge is a sorted analogue of append for wallets, where the ordering of the
// origin list is preserved by inserting new wallets at the correct position.
//
// The original slice is assumed to be already sorted by URL.
func merge(slice []Wallet, wallets ...Wallet) []Wallet {
	for _, wallet := range wallets {
		n := sort.Search(len(slice), func(i int) bool { return slice[i].URL().Cmp(wallet.URL()) >= 0 })
		if n == len(slice) {
			slice = append(slice, wallet)
			continue
		}
		slice = append(slice[:n], append([]Wallet{wallet}, slice[n:]...)...)
	}
	return slice
}

// drop is the couterpart of merge, which looks up wallets from within the sorted
// cache and removes the ones specified.
func drop(slice []Wallet, wallets ...Wallet) []Wallet {
	for _, wallet := range wallets {
		n := sort.Search(len(slice), func(i int) bool { return slice[i].URL().Cmp(wallet.URL()) >= 0 })
		if n == len(slice) {
			// Wallet not found, may happen during startup
			continue
		}
		slice = append(slice[:n], slice[n+1:]...)
	}
	return slice
}

func GetManager() *Manager {
	if INSTANCE.Load() == nil {
		//am,_,err := makeAccountManager(false,"",node.DefaultDataDir())
		//if err != nil {
		//	return nil
		//}
		//INSTANCE.Store(am)
		return nil
	}
	return INSTANCE.Load().(*Manager)
}
