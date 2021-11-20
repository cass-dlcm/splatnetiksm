package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/frankenbeanies/uuid4"
)

var optOutStr = "skip"

func enterCookie() (*string, error) {
	var newCookie string

	if _, err := fmt.Println("Go to the page below to find instructions to obtain your iksm_session cookie:\nhttps://github.com/frozenpandaman/splatnet2statink/wiki/mitmproxy-instructions\nEnter it here: "); err != nil {
		return nil, err
	}

	if _, err := fmt.Scanln(&newCookie); err != nil {
		return nil, err
	}

	for len(newCookie) != 40 {
		if _, err := fmt.Println("Cookie is invalid. Please enter it again.\nCookie: "); err != nil {
			return nil, err
		}

		if _, err := fmt.Scanln(&newCookie); err != nil {
			return nil, err
		}
	}

	return &newCookie, nil
}

func getSessionToken(sessionTokenCode string, authCodeVerifier string, client *http.Client) (sessionToken *string, errs []error) {
	bodyMarshalled := strings.NewReader(url.Values{
		"client_id":                   []string{"71b963c1b7b6d119"},
		"session_token_code":          []string{sessionTokenCode},
		"session_token_code_verifier": []string{strings.ReplaceAll(authCodeVerifier, "=", "")},
	}.Encode())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", "https://accounts.nintendo.com/connect/1.0.0/api/session_token", bodyMarshalled)
	if err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	req.Header = http.Header{
		"User-Agent":      []string{"OnlineLounge/1.13.2 NASDKAPI Android"},
		"Accept-Language": []string{"en-US"},
		"Accept":          []string{"application/json"},
		"Content-Type":    []string{"application/x-www-form-urlencoded"},
		"Content-Length":  []string{"540"},
		"Host":            []string{"accounts.nintendo.com"},
		"Connection":      []string{"Keep-Alive"},
		"Accept-Encoding": []string{"gzip"},
	}

	resp, err := client.Do(req)
	if err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			errs = append(errs, err)
		}
	}()

	type SessionTokenData struct {
		Code         string `json:"code"`
		SessionToken string `json:"session_token"`
	}

	var data SessionTokenData

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	return &data.SessionToken, nil
}

func getHashFromS2sAPI(idToken string, timestamp int, version string, client *http.Client) (hash *string, errs []error) {
	reqData := url.Values{
		"naIdToken": []string{idToken},
		"timestamp": []string{fmt.Sprint(timestamp)},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", "https://elifessler.com/s2s/api/gen2", strings.NewReader(reqData.Encode()))
	if err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	req.Header = http.Header{
		"Content-Type":   []string{"application/x-www-form-urlencoded"},
		"Content-Length": []string{strconv.Itoa(len(reqData.Encode()))},
		"User-Agent":     []string{"cassdlcmgoiksm/" + version},
	}

	resp, err := client.Do(req)
	if err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			errs = append(errs, err)
		}
	}()

	type S2sAPIHash struct {
		Hash string `json:"hash"`
	}

	var apiResponse S2sAPIHash
	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	return &apiResponse.Hash, nil
}

type flapgAPIData struct {
	Result flapgAPIDataResult `json:"result"`
}

type flapgAPIDataResult struct {
	F  string `json:"f"`
	P1 string `json:"p1"`
	P2 string `json:"p2"`
	P3 string `json:"p3"`
}

func callFlapgAPI(idToken string, guid string, timestamp int, fType string, version string, client *http.Client) (*flapgAPIData, []error) {
	var errs []error
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "https://flapg.com/ika2/api/login?public", nil)
	if err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	hash, errs2 := getHashFromS2sAPI(idToken, timestamp, version, client)
	if len(errs2) > 0 {
		errs = append(errs, errs2...)
		return nil, errs
	}

	req.Header = http.Header{
		"x-token": []string{idToken},
		"x-time":  []string{fmt.Sprint(timestamp)},
		"x-guid":  []string{guid},
		"x-hash":  []string{*hash},
		"x-ver":   []string{"3"},
		"x-iid":   []string{fType},
	}

	resp, err := client.Do(req)
	if err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			errs = append(errs, err)
		}
	}()

	resultData := flapgAPIData{}

	if err := json.NewDecoder(resp.Body).Decode(&resultData); err != nil && err != errors.New("unexpected end of JSON input") && err != io.EOF {
		errs = append(errs, err)
		return nil, errs
	}

	return &resultData, nil
}

type idResponseS struct {
	AccessToken string   `json:"access_token"`
	ExpiresIn   int      `json:"expires_in"`
	IDToken     string   `json:"id_token"`
	Scope       []string `json:"scope"`
	TokenType   string   `json:"token_type"`
}

func getIDResponse(userLang string, sessionToken string, client *http.Client) (*idResponseS, []error) {
	var errs []error
	body, err := json.Marshal(map[string]string{
		"client_id":     "71b963c1b7b6d119", // Splatoon 2 service
		"session_token": sessionToken,
		"grant_type":    "urn:ietf:params:oauth:grant-type:jwt-bearer-session-token",
	})
	if err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", "https://accounts.nintendo.com/connect/1.0.0/api/token", bytes.NewReader(body))
	if err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	req.Header = http.Header{
		"Host":            []string{"accounts.nintendo.com"},
		"Accept-Encoding": []string{"gzip deflate"},
		"Content-Type":    []string{"application/json; charset=utf-8"},
		"Accept-Language": []string{userLang},
		"Content-Length":  []string{"439"},
		"Accept":          []string{"application/json"},
		"Connection":      []string{"Keep-Alive"},
		"User-Agent":      []string{"OnlineLounge/1.13.2 NASDKAPI Android"},
	}

	resp, err := client.Do(req)
	if err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			errs = append(errs, err)
		}
	}()
	var idResp idResponseS
	if err := json.NewDecoder(resp.Body).Decode(&idResp); err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	return &idResp, nil
}

type userInfoS struct {
	Analyticsoptedin          bool `json:"analyticsOptedIn"`
	Analyticsoptedinupdatedat int  `json:"analyticsOptedInUpdatedAt"`
	Analyticspermissions      struct {
		Internalanalysis struct {
			Permitted bool `json:"permitted"`
			Updatedat int  `json:"updatedAt"`
		} `json:"internalAnalysis"`
		Targetmarketing struct {
			Permitted bool `json:"permitted"`
			Updatedat int  `json:"updatedAt"`
		} `json:"targetMarketing"`
	} `json:"analyticsPermissions"`
	Birthday      string `json:"birthday"`
	Candidatemiis []struct {
		Updatedat     int    `json:"updatedAt"`
		Favoritecolor string `json:"favoriteColor"`
		Type          string `json:"type"`
		Clientid      string `json:"clientId"`
		Storedata     struct {
			Num3 string `json:"3"`
		} `json:"storeData"`
		ID               string `json:"id"`
		Imageuritemplate string `json:"imageUriTemplate"`
		Imageorigin      string `json:"imageOrigin"`
		Etag             string `json:"etag"`
	} `json:"candidateMiis"`
	Clientfriendsoptedin          bool   `json:"clientFriendsOptedIn"`
	Clientfriendsoptedinupdatedat int    `json:"clientFriendsOptedInUpdatedAt"`
	Country                       string `json:"country"`
	Createdat                     int    `json:"createdAt"`
	Eachemailoptedin              struct {
		Deals struct {
			Optedin   bool `json:"optedIn"`
			Updatedat int  `json:"updatedAt"`
		} `json:"deals"`
		Survey struct {
			Optedin   bool `json:"optedIn"`
			Updatedat int  `json:"updatedAt"`
		} `json:"survey"`
	} `json:"eachEmailOptedIn"`
	Emailoptedin          bool   `json:"emailOptedIn"`
	Emailoptedinupdatedat int    `json:"emailOptedInUpdatedAt"`
	Emailverified         bool   `json:"emailVerified"`
	Gender                string `json:"gender"`
	ID                    string `json:"id"`
	Ischild               bool   `json:"isChild"`
	Language              string `json:"language"`
	Mii                   struct {
		Clientid string `json:"clientId"`
		Coredata struct {
			Num4 string `json:"4"`
		} `json:"coreData"`
		Etag             string `json:"etag"`
		Favoritecolor    string `json:"favoriteColor"`
		ID               string `json:"id"`
		Imageorigin      string `json:"imageOrigin"`
		Imageuritemplate string `json:"imageUriTemplate"`
		Storedata        struct {
			Num3 string `json:"3"`
		} `json:"storeData"`
		Type      string `json:"type"`
		Updatedat int    `json:"updatedAt"`
	} `json:"mii"`
	Nickname   string      `json:"nickname"`
	Region     interface{} `json:"region"`
	Screenname string      `json:"screenName"`
	Timezone   struct {
		ID               string `json:"id"`
		Name             string `json:"name"`
		Utcoffset        string `json:"utcOffset"`
		Utcoffsetseconds int    `json:"utcOffsetSeconds"`
	} `json:"timezone"`
	Updatedat int `json:"updatedAt"`
}

func getUserInfo(userLang string, idResponse idResponseS, client *http.Client) (*userInfoS, []error) {
	var errs []error
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.accounts.nintendo.com/2.0.0/users/me", nil)
	if err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	req.Header = http.Header{
		"User-Agent":      []string{"OnlineLounge/1.13.2 NASDKAPI Android"},
		"Accept-Language": []string{userLang},
		"Accept":          []string{"application/json"},
		"Authorization":   []string{"Bearer " + idResponse.AccessToken},
		"Host":            []string{"api.accounts.nintendo.com"},
		"Connection":      []string{"Keep-Alive"},
		"Accept-Encoding": []string{"gzip deflate"},
	}

	resp, err := client.Do(req)
	if err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			errs = append(errs, err)
		}
	}()

	var userInfo userInfoS

	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	return &userInfo, nil
}

type splatoonTokenS struct {
	Correlationid string `json:"correlationId"`
	Result        struct {
		Firebasecredential struct {
			Accesstoken interface{} `json:"accessToken"`
			Expiresin   int         `json:"expiresIn"`
		} `json:"firebaseCredential"`
		User struct {
			ID         int64  `json:"id"`
			Imageuri   string `json:"imageUri"`
			Membership struct {
				Active bool `json:"active"`
			} `json:"membership"`
			Name      string `json:"name"`
			Supportid string `json:"supportId"`
		} `json:"user"`
		Webapiservercredential struct {
			Accesstoken string `json:"accessToken"`
			Expiresin   int    `json:"expiresIn"`
		} `json:"webApiServerCredential"`
	} `json:"result"`
	Status int `json:"status"`
}

func getSplatoonToken(userLang string, idResponse idResponseS, userInfo userInfoS, guid string, timestamp int, version string, client *http.Client) (*splatoonTokenS, []error) {
	var errs []error
	idToken := idResponse.AccessToken
	flapgNso, errs2 := callFlapgAPI(idToken, guid, timestamp, "nso", version, client)
	if len(errs2) > 0 {
		errs = append(errs, errs2...)
		return nil, errs
	}
	bodyJSON, err := json.Marshal(map[string]map[string]interface{}{
		"parameter": {
			"f":          flapgNso.Result.F,
			"naIdToken":  flapgNso.Result.P1,
			"timestamp":  flapgNso.Result.P2,
			"requestId":  flapgNso.Result.P3,
			"naCountry":  userInfo.Country,
			"naBirthday": userInfo.Birthday,
			"language":   userInfo.Language,
		},
	})
	if err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api-lp1.znc.srv.nintendo.net/v1/Account/Login", bytes.NewReader(bodyJSON))
	if err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	req.Header = http.Header{
		"Host":             []string{"api-lp1.znc.srv.nintendo.net"},
		"Accept-Language":  []string{userLang},
		"User-Agent":       []string{"com.nintendo.znca/1.13.2 (Android/7.1.2)"},
		"Accept":           []string{"application/json"},
		"X-ProductVersion": []string{"1.13.2"},
		"Content-Type":     []string{"application/json; charset=utf-8"},
		"Connection":       []string{"Keep-Alive"},
		"Authorization":    []string{"Bearer"},
		"X-Platform":       []string{"Android"},
		"Accept-Encoding":  []string{"gzip deflate"},
	}

	resp, err := client.Do(req)
	if err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			errs = append(errs, err)
		}
	}()

	var splatoonToken splatoonTokenS

	if err := json.NewDecoder(resp.Body).Decode(&splatoonToken); err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	return &splatoonToken, nil
}

type splatoonAccessTokenS struct {
	Correlationid string `json:"correlationId"`
	Result        struct {
		Accesstoken string `json:"accessToken"`
		Expiresin   int    `json:"expiresIn"`
	} `json:"result"`
	Status int `json:"status"`
}

func getSplatoonAccessToken(splatoonToken splatoonTokenS, guid string, timestamp int, version string, client *http.Client) (*splatoonAccessTokenS, []error) {
	var errs []error
	idToken := splatoonToken.Result.Webapiservercredential.Accesstoken
	flapgApp, errs2 := callFlapgAPI(idToken, guid, timestamp, "app", version, client)
	if len(errs2) > 0 {
		errs = append(errs, errs2...)
		return nil, errs
	}
	bodyJSON, err := json.Marshal(map[string]map[string]interface{}{
		"parameter": {
			"id":                int64(5741031244955648),
			"f":                 flapgApp.Result.F,
			"registrationToken": flapgApp.Result.P1,
			"timestamp":         flapgApp.Result.P2,
			"requestId":         flapgApp.Result.P3,
		},
	})
	if err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api-lp1.znc.srv.nintendo.net/v2/Game/GetWebServiceToken", bytes.NewReader(bodyJSON))
	if err != nil {
		log.Panicln(err)
	}

	req.Header = http.Header{
		"Host":             []string{"api-lp1.znc.srv.nintendo.net"},
		"User-Agent":       []string{"com.nintendo.znca/1.13.2 (Android/7.1.2)"},
		"Accept":           []string{"application/json"},
		"X-ProductVersion": []string{"1.13.2"},
		"Content-Type":     []string{"application/json; charset=utf-8"},
		"Connection":       []string{"Keep-Alive"},
		"Authorization":    []string{"Bearer " + idToken},
		"Content-Length":   []string{"37"},
		"X-Platform":       []string{"Android"},
		"Accept-Encoding":  []string{"gzip deflate"},
	}

	resp, err := client.Do(req)
	if err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			errs = append(errs, err)
		}
	}()

	var splatoonAccessToken splatoonAccessTokenS

	if err := json.NewDecoder(resp.Body).Decode(&splatoonAccessToken); err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	return &splatoonAccessToken, nil
}

func getCookie(userLang, sessionToken, version string, client *http.Client) (*string, []error) {
	var errs []error
	timestamp := int(time.Now().Unix())
	guid := uuid4.New().String()
	idResponse, errs2 := getIDResponse(userLang, sessionToken, client)
	if len(errs2) > 0 {
		errs = append(errs, errs2...)
		return nil, errs
	}
	userInfo, errs2 := getUserInfo(userLang, *idResponse, client)
	if len(errs2) > 0 {
		errs = append(errs, errs2...)
		return nil, errs
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "https://app.splatoon2.nintendo.net/?lang="+userLang, nil)
	if err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	splatToken, errs2 := getSplatoonToken(userLang, *idResponse, *userInfo, guid, timestamp, version, client)
	if len(errs2) > 0 {
		errs = append(errs, errs2...)
		return nil, errs
	}
	splatAccess, errs2 := getSplatoonAccessToken(*splatToken, guid, timestamp, version, client)
	if len(errs2) > 0 {
		errs = append(errs, errs2...)
		return nil, errs
	}

	req.Header = http.Header{
		"Host":                    []string{"app.splatoon2.nintendo.net"},
		"X-IsAppAnalyticsOptedIn": []string{"false"},
		"Accept":                  []string{"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		"Accept-Encoding":         []string{"gzip deflate"},
		"X-GameWebToken": 		[]string{splatAccess.Result.Accesstoken},
		"Accept-Language":      []string{userLang},
		"X-IsAnalyticsOptedIn": []string{"false"},
		"Connection":           []string{"keep-alive"},
		"DNT":                  []string{"0"},
		"User-Agent":           []string{"Mozilla/5.0 (Linux; Android 7.1.2; Pixel Build/NJH47D; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36"},
		"X-Requested-With":     []string{"com.nintendo.znca"},
	}

	resp, err := client.Do(req)
	if err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			errs = append(errs, err)
		}
	}()

	for _, cookie := range resp.Cookies() {
		if cookie.Name == "iksm_session" {
			return &cookie.Value, nil
		}
	}

	return nil, errs
}

func printCookieGenReason(reason string) error {
	if reason == "blank" {
		if _, err := fmt.Println("Blank cookie."); err != nil {
			return err
		}
	} else if reason == "auth" { // authentication error
		if _, err := fmt.Println("The stored cookie has expired."); err != nil {
			return err
		}
	} else { // server error or player hasn't battled before
		if _, err := fmt.Println("Cannot access SplatNet 2 without having played at least one battle online."); err != nil {
			return err
		}
		os.Exit(1)
	}
	return nil
}

func setSessionToken(sessionToken string, client *http.Client) (*string, []error) {
	var errs []error
	if sessionToken == "" {
		if _, err := fmt.Println("session_token is blank. Please log in to your Nintendo Account to obtain your session_token."); err != nil {
			errs = append(errs, err)
			return nil, errs
		}
		newToken, errs2 := logIn(client)
		if len(errs2) > 0 {
			errs = append(errs, errs2...)
			return nil, errs
		}
		if newToken == nil {
			if _, err := fmt.Println("There was a problem logging you in. Please try again later."); err != nil {
				errs = append(errs, err)
				return nil, errs
			}
		} else {
			if *newToken == optOutStr { // user has opted to manually enter cookie
				if _, err := fmt.Println("\nYou have opted against automatic cookie generation and must manually input your iksm_session cookie."); err != nil {
					errs = append(errs, err)
					return nil, errs
				}
			} else {
				if _, err := fmt.Println("\nWrote session_token to config.txt."); err != nil {
					errs = append(errs, err)
					return nil, errs
				}
			}
		}
		return newToken, nil
	} else if sessionToken == optOutStr {
		if _, err := fmt.Println("\nYou have opted against automatic cookie generation and must manually input your iksm_session cookie. You may clear this setting by removing \"" + optOutStr + "\" from the session_token field in config.txt."); err != nil {
			errs = append(errs, err)
			return nil, errs
		}
	}
	return &sessionToken, nil
}

// GenNewCookie attempts to generate a new cookie in case the provided one is invalid.
func GenNewCookie(userLang, sessionToken, reason, version string, client *http.Client) (*string, *string, []error) {
	var errs []error
	err := printCookieGenReason(reason)
	if err != nil {
		errs = append(errs, err)
		return nil, nil, errs
	}

	seshTok, errs2 := setSessionToken(sessionToken, client)
	if len(errs2) > 0 {
		errs = append(errs, errs2...)
		return nil, nil, errs
	}

	if *seshTok == optOutStr {
		cookie, err := enterCookie()
		if err != nil {
			errs = append(errs, err)
			return nil, nil, errs
		}
		return &optOutStr, cookie, nil
	}
	if _, err := fmt.Println("Attempting to generate new cookie..."); err != nil {
		errs = append(errs, err)
		return nil, nil, errs
	}
	cookie, errs2 := getCookie(userLang, *seshTok, version, client)
	if len(errs2) > 0 {
		errs = append(errs, errs2...)
		return nil, nil, errs
	}
	return seshTok, cookie, nil
}

func logIn(client *http.Client) (*string, []error) {
	var errs []error
	authStateUnencoded := make([]byte, 36)
	if _, err := rand.Read(authStateUnencoded); err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	authState := base64.RawURLEncoding.EncodeToString(authStateUnencoded)
	authCodeVerifierUnencoded := make([]byte, 32)

	if _, err := rand.Read(authCodeVerifierUnencoded); err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	authCodeVerifier := base64.RawURLEncoding.EncodeToString(authCodeVerifierUnencoded)
	authCodeHash := sha256.Sum256([]byte(strings.ReplaceAll(authCodeVerifier, "=", "")))
	authCodeChallenge := base64.RawURLEncoding.EncodeToString(authCodeHash[:])
	body := url.Values{
		"state":                               []string{authState},
		"redirect_uri":                        []string{"npf71b963c1b7b6d119://auth"},
		"client_id":                           []string{"71b963c1b7b6d119"},
		"scope":                               []string{"openid user user.birthday user.mii user.screenName"},
		"response_type":                       []string{"session_token_code"},
		"session_token_code_challenge":        []string{strings.ReplaceAll(authCodeChallenge, "=", "")},
		"session_token_code_challenge_method": []string{"S256"},
		"theme":                               []string{"login_form"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "https://accounts.nintendo.com/connect/1.0.0/authorize", strings.NewReader(body.Encode()))
	if err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	req.URL.RawQuery = body.Encode()

	req.Header = http.Header{
		"Host":                      []string{"accounts.nintendo.com"},
		"Connection":                []string{"keep-alive"},
		"Cache-Control":             []string{"max-age=0"},
		"Upgrade-Insecure-Requests": []string{"1"},
		"User-Agent":                []string{"Mozilla/5.0 (Linux; Android 7.1.2; Pixel Build/NJH47D; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36"},
		"Accept":                    []string{"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8n"},
		"DNT":                       []string{"1"},
		"Accept-Encoding":           []string{"gzip,deflate,br"},
	}

	postLogin := req.URL.String()

	if _, err := fmt.Println("Navigate to this URL in your browser:"); err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	if _, err := fmt.Println(postLogin); err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	if _, err := fmt.Println("Log in, right click the \"Select this account\" button, copy the link address, and paste it below:"); err != nil {
		errs = append(errs, err)
		return nil, errs
	}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	useAccountURL := scanner.Text()
	re := regexp.MustCompile("de=(.*)&")
	sessionTokenCode := re.FindAllStringSubmatch(useAccountURL, -1)
	sessionToken, errs2 := getSessionToken(sessionTokenCode[0][1], authCodeVerifier, client)
	if len(errs2) > 0 {
		errs = append(errs, errs2...)
		return nil, errs
	}

	return sessionToken, nil
}
