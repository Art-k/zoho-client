package main

import (
	inc "./include"
	"fmt"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
	"os"
)

func main() {

	inc.Log = logrus.New()

	f, err := os.OpenFile("log.txt", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		inc.Log.Fatalf("ERROR opening file: %v", err)
	}
	defer f.Close()

	err = godotenv.Load("p.env")
	if err != nil {
		inc.Log.Fatal("ERROR loading .env file")
	}

	inc.Port = os.Getenv("PORT")
	if inc.Port == "" {
		inc.Port = "55400"
	}

	w := io.MultiWriter(os.Stdout, f)
	logLevel := os.Getenv("LOG_LEVEL")
	switch logLevel {
	case "Trace":
		inc.Log.SetLevel(logrus.TraceLevel)
		fmt.Println("TraceLevel")
	case "Debug":
		inc.Log.SetLevel(logrus.DebugLevel)
		fmt.Println("DebugLevel")
	case "Info":
		inc.Log.SetLevel(logrus.InfoLevel)
		fmt.Println("InfoLevel")
	case "Warn":
		inc.Log.SetLevel(logrus.WarnLevel)
		fmt.Println("WarnLevel")
	case "Error":
		inc.Log.SetLevel(logrus.ErrorLevel)
		fmt.Println("ErrorLevel")
	case "Fatal":
		inc.Log.SetLevel(logrus.FatalLevel)
		fmt.Println("FatalLevel")
	case "Panic":
		inc.Log.SetLevel(logrus.PanicLevel)
		fmt.Println("PanicLevel")
	default:
		inc.Log.SetLevel(logrus.InfoLevel)
	}
	inc.Log.SetOutput(w)
	inc.Log.SetReportCaller(true)

	//inc.Log.SetFormatter(&easy.Formatter{
	//	TimestampFormat: "2006-01-02 15:04:05",
	//	LogFormat:       "[%lvl%]: %time% - %msg% %file%\n",
	//})

	inc.Log.Info("Application is started")

	inc.Client = &http.Client{}

	inc.HandleDatabase()

	inc.HandleHTTPFunction()

}
