package da_store

import (
	 "fmt"
"context"
"github.com/quay/claircore"


)
func get(ctx context.Context,records []*claircore.IndexRecord)(map[string][]*claircore.Vulnerability, error) {
  
	
	results := make(map[string][]*claircore.Vulnerability)
	
	v:=&claircore.Vulnerability{

			 ID: "123",
			 Updater: "abc",
			 Name: "CVE-2020-00",
			 Description: "",
			 Links: "",
			 Severity: "",
			 NormalizedSeverity: "unknown",
			 FixedInVersion: "0",
             Package: &claircore.Package{ID: "0",
			           Name: "xyz",
			            Version: "v0.0"},
				Dist: &claircore.Distribution{},
				Repo: &claircore.Repository{},

			}

			results["0"]=append(results["0"],v)
	
	fmt.Println("HII I am in get")

	return results, nil

}