package logging

import (
	"log"
)

const (
	DebugLevel = 1
)

/// Config
func SetDefaultFlags() {
	SetFlags(log.Ldate | log.Ltime)
}

func SetDefaultTag() {
	//SetPrefix("[webrtc] ")
}

func SetLevel(level int) {
}

func SetFlags(flags int) {
	log.SetFlags(flags)
}

func SetPrefix(prefix string) {
	log.SetPrefix(prefix)
}

/// Log common
func Print(v ...interface{}) {
	log.Print(v...)
}

func Warn(v ...interface{}) {
	log.Print(v...)
}

func Fatal(v ...interface{}) {
	log.Fatal(v...)
}

/// Log with ln
func Println(v ...interface{}) {
	log.Println(v...)
}

func Warnln(v ...interface{}) {
	log.Println(v...)
}

func Fatalln(v ...interface{}) {
	log.Fatalln(v...)
}

/// Log with format
func Printf(format string, v ...interface{}) {
	log.Printf(format, v...)
}

func Warnf(format string, v ...interface{}) {
	log.Printf(format, v...)
}

func Fatalf(format string, v ...interface{}) {
	log.Fatalf(format, v...)
}
