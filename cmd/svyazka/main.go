// Command svyazka runs «Связка» — the subscription aggregator — on a Linux
// server.
//
//	svyazka init   --ip 203.0.113.7 --port 8443   prepare /var/lib/svyazka, print the password
//	svyazka run                                   start the service (systemd does this)
//	svyazka passwd                                set a new random password
//	svyazka info                                  print the panel address and the link
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"lazeyka/internal/svyazka"
)

var version = "dev"

const defaultData = "/var/lib/svyazka"

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "init":
		err = cmdInit(args)
	case "run":
		err = cmdRun(args)
	case "passwd":
		err = cmdPasswd(args)
	case "info":
		err = cmdInfo(args)
	case "version", "-v", "--version":
		fmt.Println(version)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "svyazka:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `Связка — объединение подписок в одну ссылку.

  svyazka init --ip АДРЕС [--port 8443]   подготовить данные и пароль
  svyazka run                            запустить службу
  svyazka passwd                         задать новый пароль панели
  svyazka info                           показать адрес панели и ссылку
  svyazka version

Общий флаг: --data ПАПКА (по умолчанию `+defaultData+`)
`)
	os.Exit(2)
}

func open(data string) (*svyazka.Store, error) {
	if err := os.MkdirAll(data, 0o700); err != nil {
		return nil, err
	}
	return svyazka.OpenStore(filepath.Join(data, "state.json"))
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	data := fs.String("data", defaultData, "папка данных")
	ip := fs.String("ip", "", "внешний IP-адрес сервера")
	port := fs.Int("port", 0, "порт HTTPS")
	staging := fs.Bool("staging", false, "тестовый Let's Encrypt (сертификат не будет доверенным)")
	machine := fs.Bool("machine", false, "вывод для установщика")
	fs.Parse(args)
	st, err := open(*data)
	if err != nil {
		return err
	}
	var password string
	err = st.Update(func(s *svyazka.State) error {
		if *ip != "" {
			addr := net.ParseIP(strings.TrimSpace(*ip))
			if addr == nil {
				return fmt.Errorf("«%s» — не IP-адрес", *ip)
			}
			if s.PublicIP != "" && s.PublicIP != addr.String() {
				os.Remove(filepath.Join(*data, "certs", "cert.pem")) // the old certificate names the old address
			}
			s.PublicIP = addr.String()
		}
		if s.PublicIP == "" {
			return errors.New("нужен внешний IP-адрес сервера: --ip")
		}
		if *port > 0 {
			if *port > 65535 {
				return errors.New("неверный порт")
			}
			s.Port = *port
		}
		if s.Port == 0 {
			s.Port = 443
		}
		if *staging {
			s.ACMEStaging = true
		}
		if s.PasswordHash == "" {
			password = svyazka.RandomPassword()
			s.PasswordHash = svyazka.HashPassword(password)
		}
		return nil
	})
	if err != nil {
		return err
	}
	s := st.Get()
	if *machine {
		fmt.Printf("password=%s\nport=%d\nip=%s\n", password, s.Port, s.PublicIP)
		return nil
	}
	printInfo(*data, s)
	if password != "" {
		fmt.Printf("Пароль панели:   %s\n", password)
	} else {
		fmt.Println("Пароль панели:   прежний (забыли — выполните svyazka passwd)")
	}
	return nil
}

func cmdPasswd(args []string) error {
	fs := flag.NewFlagSet("passwd", flag.ExitOnError)
	data := fs.String("data", defaultData, "папка данных")
	fs.Parse(args)
	if _, err := os.Stat(filepath.Join(*data, "state.json")); err != nil {
		return errors.New("Связка ещё не установлена: нет " + filepath.Join(*data, "state.json"))
	}
	st, err := open(*data)
	if err != nil {
		return err
	}
	pw := svyazka.RandomPassword()
	err = st.Update(func(s *svyazka.State) error {
		s.PasswordHash = svyazka.HashPassword(pw)
		s.SessionKey = svyazka.RandomToken(32)
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Printf("Новый пароль панели: %s\n(все входы в панель завершены; служба подхватит пароль сама)\n", pw)
	return nil
}

func cmdInfo(args []string) error {
	fs := flag.NewFlagSet("info", flag.ExitOnError)
	data := fs.String("data", defaultData, "папка данных")
	certOK := fs.Bool("cert-ok", false, "только проверить, есть ли настоящий сертификат (код выхода)")
	fs.Parse(args)
	if _, err := os.Stat(filepath.Join(*data, "state.json")); err != nil {
		return errors.New("Связка ещё не установлена: нет " + filepath.Join(*data, "state.json"))
	}
	st, err := open(*data)
	if err != nil {
		return err
	}
	s := st.Get()
	if *certOK {
		if _, err := realCert(*data, s.PublicIP); err != nil {
			os.Exit(1)
		}
		return nil
	}
	printInfo(*data, s)
	return nil
}

// realCert reads the saved Let's Encrypt certificate.
func realCert(data, ip string) (*x509.Certificate, error) {
	b, err := os.ReadFile(filepath.Join(data, "certs", "cert.pem"))
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("повреждён")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, err
	}
	if time.Now().After(c.NotAfter) {
		return nil, errors.New("истёк")
	}
	for _, a := range c.IPAddresses {
		if a.String() == ip {
			return c, nil
		}
	}
	return nil, errors.New("выписан на другой адрес")
}

func printInfo(data string, s *svyazka.State) {
	base := svyazka.BaseURL(s)
	fmt.Printf("Панель:          %s\n", svyazka.AdminURL(base, s))
	fmt.Printf("Ссылка подписки: %s\n", svyazka.SubURL(base, s))
	if c, err := realCert(data, s.PublicIP); err == nil {
		fmt.Printf("Сертификат:      Let's Encrypt до %s\n", c.NotAfter.Local().Format("02.01.2006 15:04"))
	} else {
		fmt.Println("Сертификат:      временный — настоящий от Let's Encrypt ещё не получен")
	}
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	data := fs.String("data", defaultData, "папка данных")
	dev := fs.String("http", "", "без HTTPS и сертификата, на этом адресе (для проверки), например 127.0.0.1:8080")
	acmeDir := fs.String("acme", "", "адрес ACME (по умолчанию Let's Encrypt)")
	http01 := fs.String("http01", ":80", "где отвечать на проверку Let's Encrypt")
	fs.Parse(args)

	logger := log.New(os.Stderr, "", 0)
	st, err := open(*data)
	if err != nil {
		return err
	}
	s := st.Get()
	if *dev == "" && s.PublicIP == "" {
		return errors.New("сначала выполните: svyazka init --ip ВНЕШНИЙ_АДРЕС")
	}
	svc := svyazka.NewService(st, *data)
	svc.Version = version
	svc.Logger = logger

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{
		Handler:           svc,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    32 << 10,
		ErrorLog:          log.New(io.Discard, "", 0), // scanners' broken handshakes
	}
	var ln net.Listener
	if *dev != "" {
		svc.DevURL = "http://" + *dev
		if ln, err = net.Listen("tcp", *dev); err != nil {
			return err
		}
	} else {
		dir := svyazka.LEProduction
		if s.ACMEStaging {
			dir = svyazka.LEStaging
		}
		if *acmeDir != "" {
			dir = *acmeDir
		}
		certs := &svyazka.CertManager{
			Dir: filepath.Join(*data, "certs"), IP: net.ParseIP(s.PublicIP), DirURL: dir, Email: s.ACMEEmail,
			HTTPAddr: *http01, Logf: svc.Logf, Errf: svc.Badf,
		}
		certs.Load()
		svc.Certs = certs
		go certs.Run(ctx)
		raw, err := net.Listen("tcp", fmt.Sprintf(":%d", s.Port))
		if err != nil {
			return fmt.Errorf("порт %d занят или недоступен: %w", s.Port, err)
		}
		ln = tls.NewListener(raw, &tls.Config{
			GetCertificate: certs.GetCertificate,
			MinVersion:     tls.VersionTLS12,
			NextProtos:     []string{"h2", "http/1.1"},
		})
	}
	svc.LoadCache()
	go svc.Run(ctx)
	svc.Logf("Связка %s запущена: %s", version, svc.BaseURL(st.Get()))

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(shut)
	logger.Print("Связка остановлена")
	return nil
}
