package smtp

import (
	"log"
	"net/smtp"
	"errors"
	"github.com/OWASP/Amass/v3/stringset"
	"time"
	"strings"
)

const (
	SmtpServer = "smtp.gmail.com:587"
	From = "amasstest1234@gmail.com"
	Subject = "Amass report"
	timeFormat    = "01/02 15:04:05 2006 MST"
)

type Report struct {
	Domains stringset.Set
	Found []string
	New bool
	FromEnumeration []time.Time
	ToEnumeration []time.Time
}

func NewReport(new bool) *Report {
	r := &Report{New: new}
	return r
}

func SendReport(domain string, to string, pass string, newReport *Report) (error) {
	var wordDomain string
	var body string

	if !newReport.New {
		body = "No new domain was found."
	} else {
		if len(newReport.Domains.Slice()) == 1 {
			wordDomain = "domain "
		} else {
			wordDomain = "domains "
		}
		body = "Tracking the " + wordDomain + strings.Join(newReport.Domains.Slice(),",") + "\n\n" +
				"Between " + newReport.FromEnumeration[0].Format(timeFormat) + " -> " + newReport.FromEnumeration[1].Format(timeFormat) + "\n" +
				"and " + newReport.ToEnumeration[0].Format(timeFormat) + " -> " + newReport.ToEnumeration[1].Format(timeFormat) + "\n\n" +
				"Found: " + strings.Join(newReport.Found,"\nFound:")
	}
	

	msg := "From: " + From + "\n" +
		"To: " + to + "\n" +
		"Subject: " + Subject + "\n\n" +
		body

	err := smtp.SendMail(SmtpServer,
		smtp.PlainAuth("", From, pass, "smtp.gmail.com"),
		From, []string{to}, []byte(msg))

	if err != nil {
		log.Printf("smtp error: %s", err)
		return errors.New("Could not send the email")
	}

	return nil
}