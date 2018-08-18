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

package db

import (
	"sync/atomic"
	"github.com/hpb-project/go-hpb/blockchain/storage"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/common/log"
)



// config instance
var DBINSTANCE = atomic.Value{}



// CreateDB creates the chain database.
func  CreateDB(config *config.Nodeconfig, name string) (hpbdb.Database, error) {

	if DBINSTANCE.Load() != nil {
		return DBINSTANCE.Load().(*hpbdb.LDBDatabase),nil
	}
	db, err := OpenDatabase(name, config.DatabaseCache, config.DatabaseHandles)
	if err != nil {
		return nil, err
	}
	if db, ok := db.(*hpbdb.LDBDatabase); ok {
		db.Meter("hpb/db/chaindata/")
	}
	DBINSTANCE.Store(db)
	return db, nil
}

// OpenDatabase opens an existing database with the given name (or creates one
// if no previous can be found) from within the node's data directory. If the
// node is an ephemeral one, a memory database is returned.
func OpenDatabase(name string, cache int, handles int) (hpbdb.Database, error) {

	if DBINSTANCE.Load() != nil {
		return DBINSTANCE.Load().(*hpbdb.LDBDatabase),nil
	}

	var cfg = config.GetHpbConfigInstance()
	if cfg.Node.DataDir == ""{
		return hpbdb.NewMemDatabase()
	}
	db, err := hpbdb.NewLDBDatabase(cfg.Node.ResolvePath(name), cache, handles)
	if err != nil {
		return nil, err
	}
	DBINSTANCE.Store(db)

	return db, nil
}

func GetHpbDbInstance() (*hpbdb.LDBDatabase) {
	if DBINSTANCE.Load() != nil {
		return DBINSTANCE.Load().(*hpbdb.LDBDatabase)
	}
	log.Warn("LDBDatabase is nil, please init tx pool first.")
	return nil
}