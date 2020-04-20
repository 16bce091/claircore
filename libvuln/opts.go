package libvuln

import (
	"fmt"
	"time"
	"context"
	"github.com/jmoiron/sqlx"
	"github.com/quay/claircore/alpine"
	"github.com/quay/claircore/aws"
	"github.com/quay/claircore/debian"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/python"
	"github.com/quay/claircore/rhel"
	"github.com/quay/claircore/ubuntu"
	"github.com/quay/claircore/internal/vulnstore"
	"github.com/quay/claircore/da_store"
)

const (
	DefaultUpdateInterval         = 30 * time.Minute
	DefaultUpdaterInitConcurrency = 10
	DefaultMaxConnPool            = 100
)
// making the struct for array of stores
type Stores struct{
	name  string
    store vulnstore.Store
	db    *sqlx.DB
}
type Opts struct {
	// the maximum size of the connection pool used by the database
	MaxConnPool int32
	// the connectiong string to the above data store implementation
	ConnString string
	// the interval in minutes which updaters will update the vulnstore
	UpdateInterval time.Duration
	// number of updaters ran in parallel while libvuln initializes. use this to tune io/cpu on library start when using many updaters
	UpdaterInitConcurrency int
	// set to true to have libindex check and potentially run migrations
	Migrations bool
	// returns the matchers to be used during libvuln runtime
	Matchers []driver.Matcher
	// returns the updaters to run on an interval
	Updaters []driver.Updater
	// a regex string to filter running updaters by
	Run string
    //Creating array of stores
    vulnStores []Stores
}

func (o *Opts) Parse(ctx context.Context) error {
	if o.ConnString == "" {
		return fmt.Errorf("no connection string provided")
	}

	// optional
	if o.UpdateInterval == 0 || o.UpdateInterval < time.Minute {
		o.UpdateInterval = DefaultUpdateInterval
	}
	if o.UpdaterInitConcurrency == 0 {
		o.UpdaterInitConcurrency = DefaultUpdaterInitConcurrency
	}
	if o.MaxConnPool == 0 {
		o.MaxConnPool = DefaultMaxConnPool
	}
	if len(o.Matchers) == 0 {
		o.Matchers = []driver.Matcher{
			&debian.Matcher{},
			&ubuntu.Matcher{},
			&alpine.Matcher{},
			&aws.Matcher{},
			&rhel.Matcher{},
			&python.Matcher{},
		}
	}
	if len(o.Updaters) == 0 {
		var err error
		o.Updaters, err = updaters()
		if err != nil {
			return fmt.Errorf("failed to create default set of updaters: %w", err)
		}
	}

	// filter out updaters if regex was passed
	if o.Run != "" {
		var err error
		o.Updaters, err = regexFilter(o.Run, o.Updaters)
		if err != nil {
			return fmt.Errorf("regex filtering of updaters failed: %w", err)
		}
	}
  //initializing da store and postgres
	daStore:=&da_store.Store{}
    db, postgresStore, err := initStore(ctx, o)

	if err != nil {
		return err
	}
    o.vulnStores=[]Stores{
		{
			name:  "postgres",
			store: postgresStore,
			db: db,
		},
        {
			name: "dastore",
			store: daStore,
			db:nil,
		},
	}
  return nil
}
