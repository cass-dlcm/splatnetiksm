package splatnetiksm

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

func enterCookie() string {
	var newCookie string

	if _, err := fmt.Println("Go to the page below to find instructions to obtain your iksm_session cookie:\nhttps://github.com/frozenpandaman/splatnet2statink/wiki/mitmproxy-instructions\nEnter it here: "); err != nil {
		log.Panicln(err)
	}

	if _, err := fmt.Scanln(&newCookie); err != nil {
		log.Panicln(err)
	}

	for len(newCookie) != 40 {
		if _, err := fmt.Println("Cookie is invalid. Please enter it again.\nCookie: "); err != nil {
			log.Panicln(err)
		}

		if _, err := fmt.Scanln(&newCookie); err != nil {
			log.Panicln(err)
		}
	}

	return newCookie
}

func getSessionToken(sessionTokenCode string, authCodeVerifier string, client *http.Client) interface{} {
	bodyMarshalled := strings.NewReader(url.Values{
		"client_id":                   []string{"71b963c1b7b6d119"},
		"session_token_code":          []string{sessionTokenCode},
		"session_token_code_verifier": []string{strings.ReplaceAll(authCodeVerifier, "=", "")},
	}.Encode())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", "https://accounts.nintendo.com/connect/1.0.0/api/session_token", bodyMarshalled)
	if err != nil {
		log.Panicln(err)
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
		log.Panicln(err)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Panicln(err)
		}
	}()

	type SessionTokenData struct {
		Code         string `json:"code"`
		SessionToken string `json:"session_token"`
	}

	var data SessionTokenData

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		log.Panicln(err)
	}

	return data.SessionToken
}

func getHashFromS2sAPI(idToken string, timestamp int, version string, client *http.Client) string {
	reqData := url.Values{
		"naIdToken": []string{idToken},
		"timestamp": []string{fmt.Sprint(timestamp)},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", "https://elifessler.com/s2s/api/gen2", strings.NewReader(reqData.Encode()))
	if err != nil {
		log.Panicln(err)
	}

	req.Header = http.Header{
		"Content-Type":   []string{"application/x-www-form-urlencoded"},
		"Content-Length": []string{strconv.Itoa(len(reqData.Encode()))},
		"User-Agent":     []string{"cassdlcmgoiksm/" + version},
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Panicln(err)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Panicln(err)
		}
	}()

	type S2sAPIHash struct {
		Hash string `json:"hash"`
	}

	var apiResponse S2sAPIHash
	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		log.Panicln(err)
	}

	return apiResponse.Hash
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

func callFlapgAPI(idToken string, guid string, timestamp int, fType string, version string, client *http.Client) flapgAPIData {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "https://flapg.com/ika2/api/login?public", nil)
	if err != nil {
		log.Panicln(err)
	}

	req.Header = http.Header{
		"x-token": []string{idToken},
		"x-time":  []string{fmt.Sprint(timestamp)},
		"x-guid":  []string{guid},
		"x-hash":  []string{getHashFromS2sAPI(idToken, timestamp, version, client)},
		"x-ver":   []string{"3"},
		"x-iid":   []string{fType},
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Panicln(err)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Panicln(err)
		}
	}()

	resultData := flapgAPIData{}

	if err := json.NewDecoder(resp.Body).Decode(&resultData); err != nil && err != errors.New("unexpected end of JSON input") && err != io.EOF {
		log.Panicln(err)
	}

	return resultData
}

type idResponseS struct {
	AccessToken string   `json:"access_token"`
	ExpiresIn   int      `json:"expires_in"`
	IDToken     string   `json:"id_token"`
	Scope       []string `json:"scope"`
	TokenType   string   `json:"token_type"`
}

func getIDResponse(userLang string, sessionToken string, client *http.Client) idResponseS {
	body, err := json.Marshal(map[string]string{
		"client_id":     "71b963c1b7b6d119", // Splatoon 2 service
		"session_token": sessionToken,
		"grant_type":    "urn:ietf:params:oauth:grant-type:jwt-bearer-session-token",
	})
	if err != nil {
		log.Panicln(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", "https://accounts.nintendo.com/connect/1.0.0/api/token", bytes.NewReader(body))
	if err != nil {
		log.Panicln(err)
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
		log.Panicln(err)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Panicln(err)
		}
	}()

	var idResponse idResponseS
	if err := json.NewDecoder(resp.Body).Decode(&idResponse); err != nil {
		log.Panicln(err)
	}

	return idResponse
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

func getUserInfo(userLang string, idResponse idResponseS, client *http.Client) userInfoS {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.accounts.nintendo.com/2.0.0/users/me", nil)
	if err != nil {
		log.Panicln(err)
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
		log.Panicln(err)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Panicln(err)
		}
	}()

	var userInfo userInfoS
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		log.Panicln(err)
	}

	return userInfo
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

func getSplatoonToken(userLang string, idResponse idResponseS, userInfo userInfoS, guid string, timestamp int, version string, client *http.Client) splatoonTokenS {
	idToken := idResponse.AccessToken
	flapgNso := callFlapgAPI(idToken, guid, timestamp, "nso", version, client).Result
	bodyJSON, err := json.Marshal(map[string]map[string]interface{}{
		"parameter": {
			"f":          flapgNso.F,
			"naIdToken":  flapgNso.P1,
			"timestamp":  flapgNso.P2,
			"requestId":  flapgNso.P3,
			"naCountry":  userInfo.Country,
			"naBirthday": userInfo.Birthday,
			"language":   userInfo.Language,
		},
	})
	if err != nil {
		log.Panicln(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api-lp1.znc.srv.nintendo.net/v1/Account/Login", bytes.NewReader(bodyJSON))
	if err != nil {
		log.Panicln(err)
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
		log.Panicln(err)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Panicln(err)
		}
	}()

	var splatoonToken splatoonTokenS
	if err := json.NewDecoder(resp.Body).Decode(&splatoonToken); err != nil {
		log.Panicln(err)
	}

	return splatoonToken
}

type splatoonAccessTokenS struct {
	Correlationid string `json:"correlationId"`
	Result        struct {
		Accesstoken string `json:"accessToken"`
		Expiresin   int    `json:"expiresIn"`
	} `json:"result"`
	Status int `json:"status"`
}

func getSplatoonAccessToken(splatoonToken splatoonTokenS, guid string, timestamp int, version string, client *http.Client) splatoonAccessTokenS {
	idToken := splatoonToken.Result.Webapiservercredential.Accesstoken
	flapgApp := callFlapgAPI(idToken, guid, timestamp, "app", version, client).Result
	bodyJSON, err := json.Marshal(map[string]map[string]interface{}{
		"parameter": {
			"id":                int64(5741031244955648),
			"f":                 flapgApp.F,
			"registrationToken": flapgApp.P1,
			"timestamp":         flapgApp.P2,
			"requestId":         flapgApp.P3,
		},
	})
	if err != nil {
		log.Panicln(err)
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
		log.Panicln(err)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Panicln(err)
		}
	}()

	var splatoonAccessToken splatoonAccessTokenS
	if err := json.NewDecoder(resp.Body).Decode(&splatoonAccessToken); err != nil {
		log.Panicln(err)
	}

	return splatoonAccessToken
}

func getCookie(userLang, sessionToken, version string, client *http.Client) string {
	timestamp := int(time.Now().Unix())
	guid := uuid4.New().String()
	idResponse := getIDResponse(userLang, sessionToken, client)
	userInfo := getUserInfo(userLang, idResponse, client)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "https://app.splatoon2.nintendo.net/?lang="+userLang, nil)
	if err != nil {
		log.Panicln(err)
	}

	req.Header = http.Header{
		"Host":                    []string{"app.splatoon2.nintendo.net"},
		"X-IsAppAnalyticsOptedIn": []string{"false"},
		"Accept":                  []string{"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		"Accept-Encoding":         []string{"gzip deflate"},
		"X-GameWebToken": []string{getSplatoonAccessToken(getSplatoonToken(
			userLang, idResponse, userInfo, guid, timestamp, version, client,
		), guid, timestamp, version, client).Result.Accesstoken},
		"Accept-Language":      []string{userLang},
		"X-IsAnalyticsOptedIn": []string{"false"},
		"Connection":           []string{"keep-alive"},
		"DNT":                  []string{"0"},
		"User-Agent":           []string{"Mozilla/5.0 (Linux; Android 7.1.2; Pixel Build/NJH47D; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36"},
		"X-Requested-With":     []string{"com.nintendo.znca"},
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Panicln(err)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Panicln(err)
		}
	}()

	for _, cookie := range resp.Cookies() {
		if cookie.Name == "iksm_session" {
			return cookie.Value
		}
	}

	return ""
}

func printCookieGenReason(reason string) {
	if reason == "blank" {
		if _, err := fmt.Println("Blank cookie."); err != nil {
			log.Panicln(err)
		}
	} else if reason == "auth" { // authentication error
		if _, err := fmt.Println("The stored cookie has expired."); err != nil {
			log.Panicln(err)
		}
	} else { // server error or player hasn't battled before
		if _, err := fmt.Println("Cannot access SplatNet 2 without having played at least one battle online."); err != nil {
			log.Panicln(err)
		}
		os.Exit(1)
	}
}

func setSessionToken(sessionToken string, client *http.Client) string {
	if sessionToken == "" {
		if _, err := fmt.Println("session_token is blank. Please log in to your Nintendo Account to obtain your session_token."); err != nil {
			log.Panicln(err)
		}
		newToken := logIn(client)
		if newToken == nil {
			if _, err := fmt.Println("There was a problem logging you in. Please try again later."); err != nil {
				log.Panicln(err)
			}
		} else {
			if *newToken == optOutStr { // user has opted to manually enter cookie
				if _, err := fmt.Println("\nYou have opted against automatic cookie generation and must manually input your iksm_session cookie."); err != nil {
					log.Panicln(err)
				}
			} else {
				if _, err := fmt.Println("\nWrote session_token to config.txt."); err != nil {
					log.Panicln(err)
				}
			}
		}
		return *newToken
	} else if sessionToken == optOutStr {
		if _, err := fmt.Println("\nYou have opted against automatic cookie generation and must manually input your iksm_session cookie. You may clear this setting by removing \"" + optOutStr + "\" from the session_token field in config.txt."); err != nil {
			log.Panicln(err)
		}
	}
	return sessionToken
}

// GenNewCookie attempts to generate a new cookie in case the provided one is invalid.
func GenNewCookie(userLang, sessionToken, reason, version string, client *http.Client) (string, string) {
	printCookieGenReason(reason)

	newSessionToken := setSessionToken(sessionToken, client)

	if newSessionToken == optOutStr {
		newCookie := enterCookie()
		return optOutStr, newCookie
	}
	if _, err := fmt.Println("Attempting to generate new cookie..."); err != nil {
		log.Panicln(err)
	}
	newCookie := getCookie(userLang, newSessionToken, version, client)
	return newSessionToken, newCookie
}

func logIn(client *http.Client) *string {
	authStateUnencoded := make([]byte, 36)
	if _, err := rand.Read(authStateUnencoded); err != nil {
		log.Panicln(err)
	}

	authState := base64.RawURLEncoding.EncodeToString(authStateUnencoded)
	authCodeVerifierUnencoded := make([]byte, 32)

	if _, err := rand.Read(authCodeVerifierUnencoded); err != nil {
		log.Panicln(err)
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
		log.Panicln(err)
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
		log.Panicln(err)
	}

	if _, err := fmt.Println(postLogin); err != nil {
		log.Panicln(err)
	}

	if _, err := fmt.Println("Log in, right click the \"Select this account\" button, copy the link address, and paste it below:"); err != nil {
		log.Panicln(err)
	}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	useAccountURL := scanner.Text()
	re := regexp.MustCompile("de=(.*)&")
	sessionTokenCode := re.FindAllStringSubmatch(useAccountURL, -1)
	sessionToken := getSessionToken(sessionTokenCode[0][1], authCodeVerifier, client).(string)

	return &sessionToken
}
