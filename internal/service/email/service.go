package email

import (
	"fmt"
	"net/smtp"
)

type Service interface {
	SendMail(toEmail string, subject string, body string) error
}

type MailHogService struct{}

func (s MailHogService) SendMail(toEmail string, subject string, body string) error {
	host := "localhost"
	port := "1025"

	from := "test@example.com"
	to := []string{toEmail}

	msg := []byte(
		"From: " + from + "\r\n" +
			"To: " + toEmail + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"\r\n" +
			body,
	)

	addr := host + ":" + port
	if err := smtp.SendMail(addr, nil, from, to, msg); err != nil {
		return fmt.Errorf("sending email with mailhog smtp: %w", err)
	}

	return nil
}

type Email struct {
	ToEmail string
	Subject string
	Body    string
}

type SliceEmailService struct {
	Emails []Email
}

func (s *SliceEmailService) SendMail(toEmail string, subject string, body string) error {
	s.Emails = append(s.Emails, Email{toEmail, subject, body})
	return nil
}
