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
				"xxx",	// your consumer key got form yahoo developer website
				"xxxxx",// your consumer secret got form yahoo developer website
				"http://localhost/callback"),
		}
		http.HandleFunc("/", srv.welcome)
		http.HandleFunc("/callback", srv.callback)
		http.ListenAndServe(":80", nil)
	}

