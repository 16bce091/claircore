package libvuln

import (
	"context"

	"github.com/google/uuid"
//	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/matcher"
	"github.com/quay/claircore/internal/vulnstore"
	"github.com/quay/claircore/libvuln/driver"
	 _ "github.com/quay/claircore/da_store"
)

// Libvuln exports methods for scanning an IndexReport and created
// a VulnerabilityReport.
//
// Libvuln also runs background updaters which keep the vulnerability
// database consistent.

type Libvuln struct {
    // declaring array of stores
    stores       []Stores
	matchers     []driver.Matcher
	killUpdaters context.CancelFunc
}

// New creates a new instance of the Libvuln library
func New(ctx context.Context, opts *Opts) (*Libvuln, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "libvuln/New").
		Logger()
	ctx = log.WithContext(ctx)
	err := opts.Parse(ctx)
	if err != nil {
		return nil, err
	}
	log.Info().
		Int32("count", opts.MaxConnPool).
		Msg("initializing store")
	//db, postgresstore, err := initStore(ctx, opts)
	// if err != nil {
	// 	return nil, err
	// }
	eC := make(chan error, 1024)
	dC := make(chan context.CancelFunc, 1)
	// block on updater initialization.
	log.Info().Msg("updater initialization start")
//	go initUpdaters(ctx, opts, opts.vulnStores[0].db, opts.vulnStores[0].store, dC, eC)
   go initUpdaters(ctx,opts,dC,eC)
	killUpdaters:=<-dC
	
	log.Info().Msg("updater initialization done")
	for err := range eC {
		log.Warn().
			Err(err).
			Msg("updater error")
	}
	l := &Libvuln{
//		Initializing array of stores from opts 
        stores: opts.vulnStores,
		matchers:     opts.Matchers,
		killUpdaters: killUpdaters,
	}
	log.Info().Msg("libvuln initialized")
	return l, nil
}

// Scan creates a VulnerabilityReport given a manifest's IndexReport.
func (l *Libvuln) Scan(ctx context.Context, ir *claircore.IndexReport) (*claircore.VulnerabilityReport, error) {
//Passing array of stores to the match function
	v:=[]vulnstore.Store{
		l.stores[0].store,
		l.stores[1].store,
	}
	return matcher.Match(ctx, ir, l.matchers,v)
}

// UpdateOperations returns UpdateOperations in date descending order keyed by the
// Updater name

// Looping for the stores(postgress and dastore)
func (l *Libvuln) UpdateOperations(ctx context.Context, updaters ...string) (map[string][]driver.UpdateOperation, error) {
	results:=make(map[string][]driver.UpdateOperation)
    for _,stores:=range l.stores{
		result,err:=stores.store.GetUpdateOperations(ctx, updaters...)
	    if result==nil{
		   continue
	    }
	    if err!=nil{
		   return result,err
	    }
      results=result
	}
  return results,nil
}

// DeleteUpdateOperations removes one or more update operations and their
// associated vulnerabilities from the vulnerability database.
func (l *Libvuln) DeleteUpdateOperations(ctx context.Context, ref ...uuid.UUID) error {
	for _,stores:=range l.stores{
      err:=stores.store.DeleteUpdateOperations(ctx, ref...)
      if err!=nil{
		 return err
	  }
	}
  return nil
}

// UpdateDiff returns an UpdateDiff describing the changes between prev
// and cur.
func (l *Libvuln) UpdateDiff(ctx context.Context, prev, cur uuid.UUID) (*driver.UpdateDiff, error) {
   for _,stores:=range l.stores{
	   result,err:= stores.store.GetUpdateDiff(ctx, prev, cur)
       if result==nil{
		  continue
	   }
	   if err!=nil{
	     return result,err
	   }
       return result,err
 }
	return nil,nil
}

// LatestUpdateOperations returns references for the latest update for every
// known updater.
//
// These references are okay to expose externally.
func (l *Libvuln) LatestUpdateOperations(ctx context.Context) (map[string]uuid.UUID, error) {
	results:=make(map[string]uuid.UUID)
	for _,stores:=range l.stores{
        result,err:=stores.store.GetLatestUpdateRefs(ctx)
        if result==nil{
		   continue
        }
        if err!=nil{
           return result,err
	    }
       results=result
    }
 return results,nil
}

// LatestUpdateOperation returns a reference to the latest known update.
//
// This can be used by clients to determine if a call to Scan is likely to
// return new results.
func (l *Libvuln) LatestUpdateOperation(ctx context.Context) (uuid.UUID, error) {
	for _,stores:=range l.stores{
       result,err:= stores.store.GetLatestUpdateRef(ctx)
       if result==uuid.Nil{
		  continue
       }
       if err!=nil{
		  return result,err
	   }
      return result,err
	}
return uuid.Nil,nil
}
