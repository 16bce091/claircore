package da_store

import (
	"context"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/vulnstore"
    
)


type Store struct{
   
}




func (s Store) Get(ctx context.Context, records []*claircore.IndexRecord, opts vulnstore.GetOpts) (map[string][]*claircore.Vulnerability, error) {
	// filter out the python packages by looping for the records
	


	log := zerolog.Ctx(ctx).With().
	Str("component", "internal/vulnstore/da_store").
	Logger()
ctx = log.WithContext(ctx)

log.Debug().
	Int("interested", len(records)).
	Msg("Counting python packages in DA_store")

log.Info().Msg("Calling Get of DA Store")
	vulns, err := get(ctx,records)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerabilites: %v", err)
	}
	return vulns,nil
}