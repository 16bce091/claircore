package da_store

import (
	 "fmt"
"context"
"github.com/quay/claircore"


)
func get(ctx context.Context,records []*claircore.IndexRecord)(map[string][]*claircore.Vulnerability, error) {
  
//	 fmt.Println("Inside get printing",records)

   fmt.Println("Inside da store get")
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

	  


	 for _, value := range records{
		 //fmt.Println(k)
		 
		 if(value.Package.Name=="flask" && value.Package.Version=="0.12"){
		 
			results["0"]=append(results["0"],v)

			return results,nil
		 }

	//	 fmt.Printf("%v %v",value.Package.Name,value.Package.Version)
		 
	 }
	
	
	

	
	
	fmt.Println("HII I am in get")

	return results, nil

}