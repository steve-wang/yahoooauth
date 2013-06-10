package yahoooauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"
)

type Profile struct {
	Guid string `json:"guid"`
	Name string `json:"nickname"`
}

func encodeParams(params url.Values) string {
	if len(params) == 0 {
		return ""
	}
	keys := make([]string, 0, len(params))
	for k, _ := range params {
		keys = append(keys, k)
	}
	sort.Sort(sort.StringSlice(keys))
	buf := bytes.NewBuffer(nil)
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte('&')
		}
		fmt.Fprintf(buf, "%s=%s", k, url.QueryEscape(params[k][0]))
	}
	return string(buf.Bytes())
}

func encodeAll(method, path string, params url.Values) string {
	return fmt.Sprintf("%s&%s&%s",
		url.QueryEscape(method),
		url.QueryEscape(path),
		url.QueryEscape(encodeParams(params)))
}

func hmac_sha1(text, key string) string {
	h := hmac.New(sha1.New, []byte(key))
	h.Write([]byte(text))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

type YahooOauth struct {
	rd                 *rand.Rand
	mutex              sync.Mutex
	id                 int
	tokens             map[string]string
	consumer_token     string
	consumer_secret    string
	callback_uri       string
	oauth_token        string
	oauth_token_secret string
	xoauth_yahoo_guid  string
}

func NewYahooOauth(consumer_token, consumer_secret, callback_uri string) *YahooOauth {
	return &YahooOauth{
		rd:              rand.New(rand.NewSource(time.Now().Unix())),
		tokens:          make(map[string]string),
		consumer_token:  consumer_token,
		consumer_secret: consumer_secret,
		callback_uri:    callback_uri,
	}
}

func (p *YahooOauth) newNonce() string {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.id++
	return fmt.Sprintf("%d+%d", p.rd.Uint32(), p.id)
}

func (p *YahooOauth) newTimeStamp() string {
	return fmt.Sprintf("%d", time.Now().Unix())
}

func (p *YahooOauth) addToken(token, secret string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.tokens[token] = secret
}

func (p *YahooOauth) popToken(token string) (string, bool) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	secret, ok := p.tokens[token]
	if !ok {
		return "", false
	}
	delete(p.tokens, token)
	return secret, true
}

func (p *YahooOauth) exchange(form url.Values) (url.Values, error) {
	oauth_token := form.Get("oauth_token")
	secret, ok := p.popToken(oauth_token)
	if !ok {
		return nil, fmt.Errorf("token(%s) is not found", oauth_token)
	}
	oauth_verifier := form.Get("oauth_verifier")
	resp, err := http.PostForm("https://api.login.yahoo.com/oauth/v2/get_token", url.Values{
		"oauth_consumer_key":     {p.consumer_token},
		"oauth_signature_method": {"plaintext"},
		"oauth_nonce":            {p.newNonce()},
		"oauth_signature":        {p.consumer_secret + "&" + secret},
		"oauth_timestamp":        {p.newTimeStamp()},
		"oauth_verifier":         {oauth_verifier},
		"oauth_version":          {"1.0"},
		"oauth_token":            {oauth_token},
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return url.ParseQuery(string(data))
}

func (p *YahooOauth) FetchResource(resource string) (io.ReadCloser, error) {
	uri := fmt.Sprintf("http://social.yahooapis.com/v1/user/%s/%s",
		p.xoauth_yahoo_guid,
		resource)
	params := url.Values{
		"format":                 {"json"},
		"realm":                  {"yahooapis.com"},
		"oauth_consumer_key":     {p.consumer_token},
		"oauth_nonce":            {p.newNonce()},
		"oauth_signature_method": {"HMAC-SHA1"},
		"oauth_timestamp":        {p.newTimeStamp()},
		"oauth_token":            {p.oauth_token},
		"oauth_version":          {"1.0"},
	}
	signature := func() string {
		txt := encodeAll("GET", uri, params)
		key := p.consumer_secret + "&" + p.oauth_token_secret
		return hmac_sha1(txt, key)
	}()
	params.Add("oauth_signature", signature)
	resp, err := http.Get(uri + "?" + params.Encode())
	if err != nil {
		return nil, err
	}
	return resp.Body, err
}

func (p *YahooOauth) RequestLoginURL() (string, error) {
	resp, err := http.Get("https://api.login.yahoo.com/oauth/v2/get_request_token?" +
		url.Values{
			"oauth_consumer_key":     {p.consumer_token},
			"oauth_nonce":            {p.newNonce()},
			"oauth_signature_method": {"plaintext"},
			"oauth_signature":        {p.consumer_secret + "&"},
			"oauth_timestamp":        {p.newTimeStamp()},
			"oauth_version":          {"1.0"},
			"xoauth_lang_pref":       {"en-us"},
			"oauth_callback":         {p.callback_uri},
		}.Encode())
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	form, err := url.ParseQuery(string(data))
	if err != nil {
		return "", err
	}
	oauth_token := form.Get("oauth_token")
	oauth_token_secret := form.Get("oauth_token_secret")
	p.addToken(oauth_token, oauth_token_secret)
	return form.Get("xoauth_request_auth_url"), nil
}

func (p *YahooOauth) FetchAccessToken(r *http.Request) error {
	r.ParseForm()
	form, err := p.exchange(r.Form)
	if err != nil {
		return err
	}
	p.oauth_token = form.Get("oauth_token")
	p.oauth_token_secret = form.Get("oauth_token_secret")
	p.xoauth_yahoo_guid = form.Get("xoauth_yahoo_guid")
	return nil
}

func (p *YahooOauth) FetchProfile() (*Profile, error) {
	resp, err := p.FetchResource("profile")
	if err != nil {
		return nil, err
	}
	defer resp.Close()
	var info struct {
		Info Profile `json:"profile"`
	}
	if err := json.NewDecoder(resp).Decode(&info); err != nil {
		return nil, err
	}
	return &info.Info, nil
}
