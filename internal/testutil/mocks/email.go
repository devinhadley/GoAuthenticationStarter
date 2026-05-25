package mocks

type MockEmailService struct {
	SendMailFn func(toEmail string, subject string, body string) error
}

func (s MockEmailService) SendMail(toEmail string, subject string, body string) error {
	if s.SendMailFn != nil {
		return s.SendMailFn(toEmail, subject, body)
	}
	return nil
}
