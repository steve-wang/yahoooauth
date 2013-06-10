yahoooauth
==========

Yahoooauth is a simple library written in Go that can let your customers login your website with their yahoo accounts, of course,  on condition that your website is built upon the power of Go.
Below is a sample that indicates how simply you can use it.

	package main
	
	import (
	"fmt"
		"github.com/steve-wang/yahoooauth"
		"net/http"
	)
	
	type Server struct {
		yahoo *yahoooauth.YahooOauth
	}
	
	func (p *Server) welcome(w http.ResponseWriter, r *http.Request) {
		redirect_uri, err := p.yahoo.RequestLoginURL()
		if err != nil {
			return
		}
		http.Redirect(w, r, redirect_uri, http.StatusFound)
	}
	
	func (p *Server) callback(w http.ResponseWriter, r *http.Request) {
		if err := p.yahoo.FetchAccessToken(r); err != nil {
			return
		}
		profile, err := p.yahoo.FetchProfile()
		if err != nil {
			return
		}
		fmt.Fprintf(w, "welcome, %s(%s)!\n", profile.Name, profile.Guid)
	}
	
	func main() {
		srv := Server{
			yahoo: yahoooauth.NewYahooOauth(
				"dj0yJmk9djNDV0RMZ1BsamVHJmQ9WVdrOWIybDBSSGhqTnpRbWNHbzlOVEl3TkRZMU16WXkmcz1jb25zdW1lcnNlY3JldCZ4PTYz",
				"66dd864d046a95e6854989ef11935a7c00b56ad7",
				"http://localhost/callback"),
		}
		http.HandleFunc("/", srv.welcome)
		http.HandleFunc("/callback", srv.callback)
		http.ListenAndServe(":80", nil)
	}

