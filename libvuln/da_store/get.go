package da_store

import ("fmt"
"context"
"github.com/quay/claircore"

)
func get(ctx context.Context,records []*claircore.IndexRecord)(map[string][]*claircore.Vulnerability, error) {

	   fmt.Println(records)
   
	   return nil,nil

}