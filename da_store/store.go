package da_store

import (
	"context"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/vulnstore"
	"github.com/google/uuid"
	"github.com/quay/claircore/libvuln/driver"
    
)


type Store struct{
   
}

var (
	_ vulnstore.Updater       = (*Store)(nil)
	_ vulnstore.Vulnerability = (*Store)(nil)
)












// store implements all interfaces in the vulnstore package






// UpdateVulnerabilities implements vulnstore.Updater.
func (s *Store) UpdateVulnerabilities(ctx context.Context, updater string, fingerprint driver.Fingerprint, vulns []*claircore.Vulnerability) (uuid.UUID, error) {
	
	 return uuid.Nil,nil
}

// GetUpdateOperations implements vulnstore.Updater.
func (s *Store) GetUpdateOperations(ctx context.Context, updater ...string) (map[string][]driver.UpdateOperation, error) {

	
	return nil,nil
}

// DeleteUpdateOperations implements vulnstore.Updater.
func (s *Store) DeleteUpdateOperations(ctx context.Context, id ...uuid.UUID) error {
	return nil
}

// GetUpdateOperationDiff implements vulnstore.Updater.
func (s *Store) GetUpdateOperationDiff(ctx context.Context, a, b uuid.UUID) (*driver.UpdateDiff, error) {
	return nil,nil
}
func (s *Store) GetUpdateDiff(ctx context.Context, a, b uuid.UUID) (*driver.UpdateDiff, error) {
	return nil,nil
}

func (s *Store) GetLatestUpdateRef(ctx context.Context) (uuid.UUID, error) {

	
	return uuid.Nil,nil
}

func (s *Store) GetLatestUpdateRefs(ctx context.Context) (map[string]uuid.UUID, error) {

//	r:=make(map[string]uuid.UUID)
	return nil,nil
}




// Get implements vulnstore.Vulnerability.


func (s *Store) Get(ctx context.Context, records []*claircore.IndexRecord, opts vulnstore.GetOpts) (map[string][]*claircore.Vulnerability, error) {
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
