package matcher

import (
	"context"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
    
	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/vulnstore"
	"github.com/quay/claircore/libvuln/driver"

	_ "github.com/quay/claircore/internal/vulnstore/da_store"
)



// Controller is a control structure used to find vulnerabilities affecting
// a set of packages.
type Controller struct {
	// an implemented Matcher
	m driver.Matcher
	// a vulnstore.Vulnerability instance for querying vulnerabilities
	store vulnstore.Vulnerability

	// include da_store

	DA_store vulnstore.Vulnerability
}

// NewController is a constructor for a Controller
func NewController(m driver.Matcher, store vulnstore.Vulnerability, DA_Store vulnstore.Vulnerability) *Controller {
	return &Controller{
		m:     m,
		store: store,

		DA_store: DA_Store,
	}
}

func (mc *Controller) Match(ctx context.Context, records []*claircore.IndexRecord) (map[string][]*claircore.Vulnerability, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "internal/matcher/Controller.Match").
		Str("matcher", mc.m.Name()).
		Logger()
	ctx = log.WithContext(ctx)
	// find the packages the matcher is interested in.
	interested := mc.findInterested(records)

	


	log.Debug().
		Int("interested", len(interested)).
		Int("records", len(records)).
		Msg("interest")


		

		
     

	// early return; do not call db at all
	if len(interested) == 0 {
		return map[string][]*claircore.Vulnerability{}, nil
	}

	dbSide, authoritative := mc.dbFilter()
	log.Debug().
		Bool("opt-in", dbSide).
		Bool("authoritative", authoritative).
		Msg("version filter compatible?")


	
	
	vulns, err := mc.query(ctx, interested, dbSide)
	if err != nil {
		return nil, err
	}
	log.Debug().
		Int("vulnerabilities", len(vulns)).
		Msg("query")

	if authoritative {
		return vulns, nil
	}
	// filter the vulns
	filteredVulns := mc.filter(interested, vulns)
	log.Debug().
		Int("filtered", len(filteredVulns)).
		Msg("filtered")
	return filteredVulns, nil
}

// DbFilter reports whether the db-side version filtering can be used, and
// whether it's authoritative.
func (mc *Controller) dbFilter() (bool, bool) {
	f, ok := mc.m.(driver.VersionFilter)
	if !ok {
		return false, false
	}
	return true, f.VersionAuthoritative()
}

func (mc *Controller) findInterested(records []*claircore.IndexRecord) []*claircore.IndexRecord {
	out := []*claircore.IndexRecord{}
	for _, record := range records {
		if mc.m.Filter(record) {
			out = append(out, record)
		}
	}
	return out
}

// Query asks the Matcher how we should query the vulnstore then performs the query and returns all
// matched vulnerabilities.
func (mc *Controller) query(ctx context.Context, interested []*claircore.IndexRecord, dbSide bool) (map[string][]*claircore.Vulnerability, error) {
	// ask the matcher how we should query the vulnstore
	matchers := mc.m.Query()
	getOpts := vulnstore.GetOpts{
		Matchers:         matchers,
		Debug:            true,
		VersionFiltering: dbSide,
	}

	

	vulns,e:=mc.DA_store.Get(ctx,interested,getOpts)

	 log.Printf("%v",e)


	matches, err := mc.store.Get(ctx, interested, getOpts)
	if err != nil {
		return nil, err
	}
   
	matches["0"]=vulns["0"]
	
	return matches, nil
}

// Filter method asks the matcher if the given package is affected by the returned vulnerability. if so; its added to a result map where the key is the package ID
// and the value is a Vulnerability. if not it is not added to the result.
func (mc *Controller) filter(interested []*claircore.IndexRecord, vulns map[string][]*claircore.Vulnerability) map[string][]*claircore.Vulnerability {
	filtered := map[string][]*claircore.Vulnerability{}
	for _, record := range interested {
		filtered[record.Package.ID] = filterVulns(mc.m, record, vulns[record.Package.ID])
	}

	// adding dummy vulns
	filtered["0"]=vulns["0"]
	return filtered
}

// filter returns only the vulnerabilities affected by the provided package.
func filterVulns(m driver.Matcher, record *claircore.IndexRecord, vulns []*claircore.Vulnerability) []*claircore.Vulnerability {
	filtered := []*claircore.Vulnerability{}
	for _, vuln := range vulns {
		if m.Vulnerable(record, vuln) {
			filtered = append(filtered, vuln)
		}
	}
	return filtered
}
