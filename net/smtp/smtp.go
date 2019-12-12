package smtp

import (
	"log"
	"net/smtp"
)

const (
	SmtpServer = "smtp.gmail.com:587"
)

func SendReport(domain string, to string, pass string) {

	from := "test243565@gmail.com"
	body := "test"

	msg := "From: " + from + "\n" +
		"To: " + to + "\n" +
		"Subject: Amass report: New subdomains found for " + domain + "\n\n" +
		body

	err := smtp.SendMail(SmtpServer,
		smtp.PlainAuth("", from, pass, "smtp.gmail.com"),
		from, []string{to}, []byte(msg))

	if err != nil {
		log.Printf("smtp error: %s", err)
		return
	}
}