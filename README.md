SplatNetIksm
================

SplatNetIksm is a Go module that obtains the `iksm_session` cookie for use with the Nintendo Switch Online Splatoon 2 libraries.

Adapted from github.com/frozenpandaman/splatnet2statink/iksm.py

## Use

Example that uses iksm to get a cookie, and then prints the 50 most recent Salmon Run shifts:

```Go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/spf13/viper"
	"log"
	"net/http"
	"time"
)

func main() {
	client := &http.Client{}
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.SetConfigType("json")
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Println("No config file found. One will be created.")
			viper.Set("cookie", "")
			viper.Set("session_token", "")
			viper.Set("user_lang", "en-US")
			if err := viper.WriteConfigAs("./config.json"); err != nil {
				log.Panicln(err)
			}
		} else {
			log.Panicf("Error reading the config file. Error is %v\n", err)
		}
	}
	viper.SetDefault("cookie", "")
	viper.SetDefault("session_token", "")
	viper.SetDefault("user_lang", "en-US")
	url := "https://app.splatoon2.nintendo.net/api/coop_results"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		log.Panicln(err)
	}

	_, timezone := time.Now().Zone()
	timezone = -timezone / 60
	req.Header = http.Header{
		"Host":              []string{"app.splatoon2.nintendo.net"},
		"x-unique-id":       []string{"32449507786579989235"},
		"x-requested-with":  []string{"XMLHttpRequest"},
		"x-timezone-offset": []string{fmt.Sprint(timezone)},
		"User-Agent":        []string{"Mozilla/5.0 (Linux; Android 7.1.2; Pixel Build/NJH47D; wv) AppleWebKit/537.36 (KHTML, like Gecko) version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36"},
		"Accept":            []string{"*/*"},
		"Referer":           []string{"https://app.splatoon2.nintendo.net/home"},
		"Accept-Encoding":   []string{"gzip deflate"},
		"Accept-Language":   []string{viper.GetString("user_lang")},
	}

	if viper.GetString("cookie") == "" {
		sessionToken, cookie, errs := GenNewCookie(viper.GetString("user_lang"), viper.GetString("session_token"), "blank", "1.0.0", client)
		if len(errs) > 0 {
			log.Panicln(errs)
        }
		viper.Set("cookie", cookie)
		viper.Set("session_token", sessionToken)
		if err := viper.WriteConfig(); err != nil {
			log.Panicln(err)
		}
	}

	req.AddCookie(&http.Cookie{Name: "iksm_session", Value: viper.GetString("cookie")})

	resp, err := client.Do(req)
	if err != nil {
		log.Panicln(err)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Panicln(err)
		}
	}()
	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		log.Panicln(err)
	}
	log.Println(data)
}

```

## License

[GPLv3](https://www.gnu.org/licenses/gpl-3.0.html)