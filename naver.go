// Package naver provides nid.naver.com authentication method.
// Auth logics are ported from https://github.com/HallaZzang/python-naverlogin.
package naver

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// const userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36"
const userAgent = "Opera/12.02 (Android 4.1; Linux; Opera Mobi/ADR-1111101157; U; en-US) Presto/2.9.201 Version/12.02"

// AuthFailed indicates nid.naver.com returned the request with failure.
type AuthFailed struct{}

// Error implements error interface.
func (err AuthFailed) Error() string {
	return "Authentication failed"
}

// Auth tries to authenticate with given ID/password, with given *http.Client.
// If client is nil, it'll be set automatically to http.DefaultClient.
// If client.Jar is nil, the jar will be set to new *cookiejar.Jar.
func Auth(id string, passwd string, client *http.Client) error {
	if client == nil {
		client = http.DefaultClient
		if client.Jar == nil {
			jar, _ := cookiejar.New(nil)
			client.Jar = jar
		}
	}
	keyname, sesskey, n, e, err := GetKeys(client)
	if err != nil {
		return err
	}

	bn := new(big.Int)
	_, err = fmt.Sscanf(e, "%x", bn)
	if err != nil {
		return err
	}
	pubkey := &rsa.PublicKey{
		N: bn,     // #blamenhn
		E: int(n), // #blamenhn
	}

	toenc := string(byte(len(sesskey))) + sesskey + string(byte(len(id))) + id + string(byte(len(passwd))) + passwd
	var enc []byte
	enc, err = rsa.EncryptPKCS1v15(rand.Reader, pubkey, []byte(toenc))
	if err != nil {
		return err
	}

	form := url.Values{}
	form.Add("enctp", "1")
	form.Add("encpw", hex.EncodeToString(enc))
	form.Add("encnm", keyname)
	form.Add("svctype", "0")
	form.Add("url", "http://www.naver.com/")
	form.Add("enc_url", "http%3A%2F%2Fwww.naver.com%2F")
	form.Add("postDataKey", "")
	form.Add("nvlong", "")
	form.Add("saveID", "")
	form.Add("smart_level", "undefined")
	form.Add("id", "")
	form.Add("pw", "")

	var req *http.Request
	req, err = http.NewRequest("POST", "https://nid.naver.com/nidlogin.login", bytes.NewBufferString(form.Encode()))
	if err != nil {
		return err
	}

	req.Header.Add("User-Agent", userAgent)
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Add("Accept-Language", "ko-KR,ko;q=0.8,en-US;q=0.5,en;q=0.3")
	req.Header.Add("Accept-Encoding", "gzip, deflate")
	req.Header.Add("Referer", "http://www.naver.com")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := getResp(client, req)
	if err != nil {
		return err
	}
	if strings.Index(resp, "https://nid.naver.com/login/sso/finalize.nhn") > -1 {
		finalizer := getRedirect(resp)

		req, err = http.NewRequest("GET", finalizer, nil)
		if err != nil {
			return err
		}
		req.Header.Add("User-Agent", userAgent)
		req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Add("Accept-Language", "ko-KR,ko;q=0.8,en-US;q=0.5,en;q=0.3")
		req.Header.Add("Accept-Encoding", "gzip, deflate")
		req.Header.Add("Referer", "https://nid.naver.com/nidlogin.login")
		resp, err = getResp(client, req)
		if err != nil {
			return err
		}

		if strings.Index(resp, `window.location.replace("http://www.naver.com/")`) > 0 {
			return nil
		}
	}
	return AuthFailed{}
}

func getResp(c *http.Client, req *http.Request) (string, error) {
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	buf := new(bytes.Buffer)
	if _, err = io.Copy(buf, resp.Body); err != nil {
		return "", err
	}

	return string(buf.Bytes()), nil
}

func getRedirect(html string) string {
	matches := regexp.MustCompile(`location\.replace\("(.+?)"\)`).FindAllStringSubmatch(string(html), -1)
	if len(matches) > 0 {
		return matches[0][1]
	}
	return ""
}

// Get is a simple method to get HTTP response in string.
func Get(url string, c *http.Client) (string, error) {
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, resp.Body)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	return string(buf.Bytes()), nil
}

// GetKeys gets required data from Naver server for authentication, with given client.
// You should not set c to nil, instead put http.DefaultClient.
func GetKeys(c *http.Client) (keyname string, sessionKey string, nvalue int64, evalue string, err error) {
	var script string
	script, err = Get("http://static.nid.naver.com/loginv3/js/keys_js.nhn", c)
	if err != nil {
		return
	}
	strf := regexp.MustCompile("(sessionkey|keyname|nvalue|evalue) = '(\\w+)'").FindAllStringSubmatch(script, -1)
	sessionKey = strf[0][2]
	keyname = strf[1][2]
	if err != nil {
		return
	}
	nvalue, err = strconv.ParseInt(strf[3][2], 16, 64)
	evalue = strf[2][2]
	return
}
