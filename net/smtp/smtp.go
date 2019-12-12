package smtp

import (
	"log"
	"net/smtp"
	"errors"
	"github.com/OWASP/Amass/v3/stringset"
)

const (
	SmtpServer = "smtp.gmail.com:587"
	From = "amasstest1234@gmail.com"
	Subject = "Amass report"
)

type Report struct {
	Domains stringset.Set
	Found []string
	New bool
}

func NewReport(domains stringset.Set, found []string, new bool) *Report {
	r := &Report{Domains: domains, Found: found, New: new}
	return r
}

func SendReport(domain string, to string, pass string, newReport *Report) (error) {

	body := "test"

	if !newReport.New {
		body = "No new domain was found."
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