package include

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"
)

var Log *logrus.Logger
var Client *http.Client
var Port string
var Version string
var Db *gorm.DB
var Err error

type DBZohoCode struct {
	gorm.Model
	Code string
}

type DBZohoToken struct {
	gorm.Model
	ZohoToken
}

type ZohoToken struct {
	AccessToken  string `json:"access_token"`  //:"1000.2deaf8d0c268e3c85daa2a013a843b10.703adef2bb337b 8ca36cfc5d7b83cf24",
	RefreshToken string `json:"refresh_token"` //:"1000.18e983526f0ca8575ea9c53b0cd5bb58.1bd83a6f2e22c3a7e1309d96ae439cc1",
	ApiDomain    string `json:"api_domain"`    //:"https://api.zoho.com",
	TokenType    string `json:"token_type"`    //:"Bearer",
	ExpiresIn    int    `json:"expires_in"`    //:3600
}

type AccessTokenResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	APIDomain    string `json:"api_domain,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	Error        string `json:"error,omitempty"`
}

type IncomingContactResponse struct {
	Status   string `json:"status,omitempty"`
	ListKey  string `json:"listkey,omitempty"`
	Code     string `json:"code,omitempty"`
	Url      string `json:"url,omitempty"`
	ListName string `json:"listname,omitempty"`
	Version  string `json:"version,omitempty"`
}

type DBIncomingContact struct {
	gorm.Model
	IncomingContact
	Processed bool
}

type IncomingContact struct {
	ListKey string
	Email   string
}

func HandleHTTPFunction() {

	r := mux.NewRouter()
	r.Use(authMiddleware)
	//r.Use(headerMiddleware)

	//TODO this part should be finished
	//r.HandleFunc("/code", ZohoCodeProcessing)
	r.HandleFunc("/token", GetZohoToken)
	r.HandleFunc("/add-contact", AddZohoContact)
	//r.HandleFunc("/get-avg-age", AvgLoopsForScreens)

	fmt.Printf("Starting Server to HANDLE zoho.maxtv.tech back end\nPort : " + Port + "\nAPI revision " + Version + "\n\n")
	if err := http.ListenAndServe(":"+Port, r); err != nil {
		Log.Fatal(err, "ERROR")
	}

}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
		} else {
			Authorization := r.Header.Get("Authorization")
			if Authorization == "Bearer "+os.Getenv("AUTH") {
				next.ServeHTTP(w, r)
			} else {
				ResponseForbidden(w, "No Auth", "")
			}
			//n, _ := fmt.Fprintf(w, "")
			//fmt.Println(n)
		}
	})
}

func ResponseForbidden(w http.ResponseWriter, message string, frontEndAction string) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	n, _ := fmt.Fprintf(w, "{\"message\":\""+message+"\", \"action\":\""+frontEndAction+"\"}")
	log.Println("Response was sent ", n, " bytes")
	return
}

func PostContactToZoho(contact DBIncomingContact) (err error) {
	//https://campaigns.zoho.com/api/v1.1/addlistsubscribersinbulk?listkey=listkey&resfmt=[JSON]&emailids=[email addresses]

	token, err := CheckForSavedTokens()
	if err != nil {
		token, err = RefreshTokenRequest()
		if err != nil {
			//TODO Msg to Telegram bot "we cant save contact to zoho"
			return fmt.Errorf("Not added to zoho, saved to temp storage ")
		}
	}

	q := url.Values{}
	q.Set("resfmt", "[JSON]")
	q.Set("listkey", contact.ListKey)
	q.Set("emailids", "['art.v.krg+my_new_sus@gmail.com']")

	URL := fmt.Sprintf("https://campaigns.zoho.com/api/v1.1/addlistsubscribersinbulk?%s", q.Encode())

	req, err := http.NewRequest("POST", URL, nil)
	if err != nil {
		return fmt.Errorf("Failed to make a request https://campaigns.zoho.com/api/v1.1/addlistsubscribersinbulk '%s' ", err)
	}
	req.Header.Set("Authorization", token.TokenType+" "+token.AccessToken)

	resp, err := Client.Do(req)
	if err != nil {
		Log.Error(err)
		return fmt.Errorf("Failed while POST contact to zoho: %s ", err)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("Failed to close request body: %s\n", err)
		}
	}()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Failed to read request body on request to https://campaigns.zoho.com/api/v1.1/addlistsubscribersinbulk?: %s ", err)
	}

	Log.Debug("Add Contact Status Code ", resp.StatusCode)
	if resp.StatusCode != 200 {
		return fmt.Errorf("Got non-200 status code from request add contact: %s\n%s", resp.Status, string(body))
	}

	//addContactResponse := IncomingContactResponse{}
	//err = json.Unmarshal(body, &addContactResponse)
	//if err != nil {
	//	Log.Error(err, string(body))
	//	return fmt.Errorf("Failed to unmarshal add contact response from request to add contact: %s ", err)
	//}

	return err
}

func PostContactsToZoho() (err error) {

	var contacts []DBIncomingContact
	Db.Where("processed = ?", false).Find(&contacts)

	for _, contact := range contacts {
		errs := PostContactToZoho(contact)
		if errs != nil {
			err = errs
		} else {
			contact.Processed = true
			Db.Save(&contact)
		}
	}
	return err

}

func AddZohoContact(w http.ResponseWriter, r *http.Request) {

	switch r.Method {

	case "POST":

		var incomingData IncomingContact
		err := json.NewDecoder(r.Body).Decode(&incomingData)
		if err != nil {
			Log.Println(err)
			ResponseBadRequest(w, err, "")
			return
		}

		var contact DBIncomingContact
		contact.ListKey = incomingData.ListKey
		contact.Email = incomingData.Email

		Db.Create(&contact)

		err = PostContactsToZoho()
		if err != nil {
			Log.Error(err)
			ResponseNotAddedToZoho(w, err.Error())
			return
		}

		ResponseOK(w, []byte(""))

	}

}

func ResponseNotAddedToZoho(w http.ResponseWriter, message string) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("content-type", "application/json")
	errorString := "{\"message\":\"" + message + "\"}"
	http.Error(w, errorString, http.StatusAccepted)
	return
}

func ResponseOK(w http.ResponseWriter, addedRecordString []byte) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	n, _ := fmt.Fprintf(w, string(addedRecordString))
	log.Println("Response was sent ", n, " bytes")
	return
}

func ResponseBadRequest(w http.ResponseWriter, err error, message string) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("content-type", "application/json")
	errorString := "{\"error_message\":\"" + err.Error() + "\",\"message\":\"" + message + "\"}"
	http.Error(w, errorString, http.StatusBadRequest)
	return
}

type GetTokenResponse struct {
	CurrentToken DBZohoToken
	Status       string
	Messages     []string
}

func GetZohoToken(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":

		tokenResponse := GetTokenResponse{}

		token := DBZohoToken{}
		Db.Last(&token)
		token, err := CheckForSavedTokens()
		if err != nil {
			tokenResponse.Messages = append(tokenResponse.Messages, err.Error())
			token, err = RefreshTokenRequest()
			if err != nil {
				tokenResponse.Messages = append(tokenResponse.Messages, err.Error())
				tokenResponse.CurrentToken = token
				tokenResponse.Status = "token is invalid"
			} else {
				tokenResponse.CurrentToken = token
				tokenResponse.Status = "token refreshed"
			}
		} else {
			tokenResponse.CurrentToken = token
			tokenResponse.Status = "token is valid"
		}

		response, err := json.Marshal(&tokenResponse)
		if err != nil {
			ResponseBadRequest(w, err, "")
		}
		ResponseOK(w, response)

	case "POST":

		err := ZohoAuth2(r.URL.Query().Get("code"))
		if err != nil {
			ResponseBadRequest(w, err, "You need to Max Tv Dev Support !!!")
			return
		}

		var token DBZohoToken
		Db.Last(&token)
		response, err := json.Marshal(&token)
		if err != nil {
			ResponseBadRequest(w, err, "We can't read Token")
			return
		}
		ResponseOK(w, response)
	default:
		ResponseBadRequest(w, nil, "Method is not allowed")
	}
}

func ZohoCodeProcessing(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case "GET":

		code := r.URL.Query().Get("code")
		Log.Info("Code is received : ", code)
		Db.Create(&DBZohoCode{
			Code: code,
		})

		url := "https://accounts.zoho.com/oauth/v2/token?" +
			"client_id=" + os.Getenv("CLIENT_ID") + "&" +
			"grant_type=authorization_code&" +
			"client_secret=" + os.Getenv("CLIENT_SECRET") + "&" +
			"redirect_uri=https://zoho.maxtv.tech/code&" +
			"code=" + code

		fmt.Println("--------------- URL to CLICK GET TOKENS -------------------------")
		fmt.Println(url)
		fmt.Println("--------------- URL to CLICK GET TOKENS -------------------------")

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)

		_, _ = fmt.Fprintf(w, "")

	case "POST":

		var codes []DBZohoCode
		Db.Order("created_at desc").Find(&codes)

		addedRecordString, _ := json.Marshal(&codes)

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusOK)
		n, _ := fmt.Fprintf(w, string(addedRecordString))
		fmt.Println("Response was sent ", n, " bytes")

	}

}

func HandleDatabase() {

	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			SlowThreshold: time.Second, // Slow SQL threshold
			LogLevel:      logger.Info, // Log level
			Colorful:      true,        // Disable color
		},
	)

	Db, Err = gorm.Open(sqlite.Open(os.Getenv("DATABASE_PATH")+"zoho.db"), &gorm.Config{
		Logger: newLogger,
	})
	if Err != nil {
		Log.Panic(Err)
		panic("ERROR failed to connect database")
	}

	err := Db.AutoMigrate(
		&DBZohoCode{},
		&DBZohoToken{},
		&DBIncomingContact{},
	)

	if err != nil {
		Log.Println("ERROR, DB AutoMigrate")
	}

}

func ZohoAuth() {

	//https://accounts.zoho.com/oauth/v2/auth
	//	?response_type=code&
	//		client_id=1000.GMB0YULZHJK411284S8I5GZ4CHUEX0&
	//		scope=ZohoCampaigns.contact.ALL&
	//		redirect_uri=https://www.zylker.com/oauthredirect&
	//	prompt=consent

	//https://accounts.zoho.com/oauth/v2/auth?client_id=1000.1KNSCLKQS192BLLGKR0BS1V452FQ5H&scope=ZohoCampaigns.campaign.ALL,Aaaserver.profile.Read,ZohoCampaigns.contact.ALL&redirect_uri=http://api.maxtvmedia.com/zoho/redirect.php&response_type=code

	url := "https://accounts.zoho.com/oauth/v2/auth?response_type=code&client_id=" + os.Getenv("CLIENT_ID") + "&scope=ZohoCampaigns.contact.ALL&redirect_uri=https://zoho.maxtv.tech/code&prompt=consent"
	fmt.Println("--------------- URL to CLICK GET CODE -------------------------")
	fmt.Println(url)
	fmt.Println("--------------- URL to CLICK GET CODE -------------------------")

	//req, err := http.NewRequest("GET", url, nil)
	//if err != nil {
	//	Log.Error(err)
	//}
	//
	//resp, err := Client.Do(req)
	//if err != nil {
	//	Log.Error(err)
	//}
	//defer resp.Body.Close()

	//time.Sleep(15 * time.Second)

	//var code DBZohoCode
	//Db.Last(&code)

	// ============================================================================

}

func CheckForSavedTokens() (token DBZohoToken, err error) {

	Db.Last(&token)
	if token.CreatedAt.After(time.Now().Add(time.Duration(token.ExpiresIn))) {
		return token, fmt.Errorf("Access Token is expired ")
	}
	return token, nil
}

func RefreshTokenRequest() (token DBZohoToken, err error) {

	Db.Last(&token)

	q := url.Values{}
	q.Set("client_id", os.Getenv("CLIENT_ID"))
	q.Set("client_secret", os.Getenv("CLIENT_SECRET"))
	q.Set("refresh_token", token.RefreshToken)
	q.Set("grant_type", "refresh_token")

	tokenURL := fmt.Sprintf("https://accounts.zoho.com/oauth/v2/token?%s", q.Encode())
	req, err := http.NewRequest("POST", tokenURL, nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := Client.Do(req)
	if err != nil {
		Log.Error(err)
		return token, fmt.Errorf("Failed while requesting generate token: %s ", err)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("Failed to close request body: %s\n", err)
		}
	}()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return token, fmt.Errorf("Failed to read request body on request to https://accounts.zoho.com/oauth/v2/token: %s ", err)
	}

	if resp.StatusCode != 200 {
		return token, fmt.Errorf("Got non-200 status code from request to refresh token: %s\n%s", resp.Status, string(body))
	}

	tokenResponse := AccessTokenResponse{}
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		return token, fmt.Errorf("Failed to unmarshal access token response from request to refresh token: %s ", err)
	}

	//If the tokenResponse is not valid it should not update local tokens
	if tokenResponse.Error == "invalid_code" {
		// TODO we need to send message to telegram or gmail with instructions
		// TODO and update code
		return token, fmt.Errorf("We need to refresh Code and send it to ZOHO client https://api-console.zoho.com/client/1000.9D2L42IWZNLWRANCSACG84QEA0VU3H ")
	}

	fmt.Println("================= REFRESHED TOKEN ===========")
	fmt.Println("Error : ", tokenResponse.Error)
	fmt.Println("TokenType : ", tokenResponse.TokenType)
	fmt.Println("ExpiresIn : ", tokenResponse.ExpiresIn)
	fmt.Println("RefreshToken : ", tokenResponse.RefreshToken)
	fmt.Println("AccessToken : ", tokenResponse.AccessToken)
	fmt.Println("APIDomain : ", tokenResponse.APIDomain)
	fmt.Println("=============================================")

	Db.Create(&DBZohoToken{
		Model: gorm.Model{},
		ZohoToken: ZohoToken{
			AccessToken:  tokenResponse.AccessToken,
			RefreshToken: tokenResponse.RefreshToken,
			ApiDomain:    tokenResponse.APIDomain,
			TokenType:    tokenResponse.TokenType,
			ExpiresIn:    tokenResponse.ExpiresIn,
		},
	})

	Db.Last(&token)

	return token, nil
}

func ZohoAuth2(code string) (err error) {

	_, err = CheckForSavedTokens()
	if err != nil {
		_, err = RefreshTokenRequest()
		return err
	}

	q := url.Values{}
	q.Set("client_id", os.Getenv("CLIENT_ID"))
	q.Set("client_secret", os.Getenv("CLIENT_SECRET"))
	q.Set("code", code)
	q.Set("redirect_uri", os.Getenv("REDIRECT_URL"))
	q.Set("grant_type", "authorization_code")

	tokenURL := fmt.Sprintf("https://accounts.zoho.com/oauth/v2/token?%s", q.Encode())

	req, err := http.NewRequest("POST", tokenURL, nil)
	if err != nil {
		return fmt.Errorf("Failed to make a request https://accounts.zoho.com/oauth/v2/token '%s' ", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := Client.Do(req)
	if err != nil {
		Log.Error(err)
		return fmt.Errorf("Failed while requesting generate token: %s ", err)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("Failed to close request body: %s\n", err)
		}
	}()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Failed to read request body on request to https://accounts.zoho.com/oauth/v2/token?: %s ", err)
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("Got non-200 status code from request to generate token: %s\n%s", resp.Status, string(body))
	}

	tokenResponse := AccessTokenResponse{}
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		return fmt.Errorf("Failed to unmarshal access token response from request to generate token: %s ", err)
	}

	//If the tokenResponse is not valid it should not update local tokens
	if tokenResponse.Error == "invalid_code" {
		// TODO we need to send message to telegram or gmail with instructions
		// TODO and update code, our scope is ZohoCampaigns.contact.ALL
		return fmt.Errorf("We need to refresh Code and send it to ZOHO client https://api-console.zoho.com/client/1000.9D2L42IWZNLWRANCSACG84QEA0VU3H ")
	}

	fmt.Println("================= TOKEN =====================")
	fmt.Println("Error : ", tokenResponse.Error)
	fmt.Println("TokenType : ", tokenResponse.TokenType)
	fmt.Println("ExpiresIn : ", tokenResponse.ExpiresIn)
	fmt.Println("RefreshToken : ", tokenResponse.RefreshToken)
	fmt.Println("AccessToken : ", tokenResponse.AccessToken)
	fmt.Println("APIDomain : ", tokenResponse.APIDomain)
	fmt.Println("=============================================")

	Db.Create(&DBZohoToken{
		Model: gorm.Model{},
		ZohoToken: ZohoToken{
			AccessToken:  tokenResponse.AccessToken,
			RefreshToken: tokenResponse.RefreshToken,
			ApiDomain:    tokenResponse.APIDomain,
			TokenType:    tokenResponse.TokenType,
			ExpiresIn:    tokenResponse.ExpiresIn,
		},
	})

	return nil

}
