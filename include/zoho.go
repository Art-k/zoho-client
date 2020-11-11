package include

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"log"
	"net/http"
	"os"
	"time"
)

var Log *logrus.Logger
var Client *http.Client
var Port string
var Version string

type DBZohoCode struct {
	gorm.Model
	Code string
}

func HandleHTTPFunction() {

	r := mux.NewRouter()
	//r.Use(authMiddleware)
	//r.Use(headerMiddleware)

	//TODO this part should be finished
	r.HandleFunc("/code", ZohoCodeProcessing)
	//r.HandleFunc("/get-avg-age", AvgLoopsForScreens)

	fmt.Printf("Starting Server to HANDLE zoho.maxtv.tech back end\nPort : " + Port + "\nAPI revision " + Version + "\n\n")
	if err := http.ListenAndServe(":"+Port, r); err != nil {
		Log.Fatal(err, "ERROR")
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

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)

		_, _ = fmt.Fprintf(w, "")

	case "POST":

		var codes []DBZohoCode
		Db.Find(&codes)

		addedRecordString, _ := json.Marshal(&codes)

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusOK)
		n, _ := fmt.Fprintf(w, string(addedRecordString))
		fmt.Println("Response was sent ", n, " bytes")

	}

}

var Db *gorm.DB
var Err error

func HandleDatabase() {

	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			SlowThreshold: time.Second,  // Slow SQL threshold
			LogLevel:      logger.Error, // Log level
			Colorful:      true,         // Disable color
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
	)

	if err != nil {
		Log.Println("ERROR, DB AutoMigrate")
	}

}

func ZohoAuth() {

	//https://accounts.zoho.com/oauth/v2/auth
	//	?response_type=code&
	//		client_id=1000.GMB0YULZHJK411284S8I5GZ4CHUEX0&
	//		scope=AaaServer.profile.Read&
	//		redirect_uri=https://www.zylker.com/oauthredirect&
	//	prompt=consent

}
