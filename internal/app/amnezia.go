package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"lazeyka/internal/amnezia"
	"lazeyka/internal/importer"
	"lazeyka/internal/logx"
	"lazeyka/internal/settings"
)

// Amnezia Premium: one key, the location chosen in Лазейка. The personal
// account issues an AmneziaWG file per location and every file takes one of
// the subscription's 7 slots, so Лазейка keeps exactly one: a new location's
// file replaces the old one, which is given back to the account. The calls
// are the account page's own, undocumented (see package amnezia).

// amneziaBase: the personal account ("" = amnezia.Panel; tests point it elsewhere).
var amneziaBase = ""

// amneziaClients: through the VPN first (the account is often blocked in
// Russia), then directly.
func (a *App) amneziaClients() []*http.Client {
	var cs []*http.Client
	if u := a.vpnProxyURL(); u != nil {
		cs = append(cs, socksClient(u, amnezia.Timeout))
	}
	return append(cs, directClient(amnezia.Timeout))
}

// amneziaRevoke remembers how the account gives a file back (read from its
// page once per run).
var amneziaRevoke struct {
	sync.Mutex
	route, field string
}

func rememberRevoke(c *amnezia.Client) {
	route, field := c.RevokeCall()
	amneziaRevoke.Lock()
	amneziaRevoke.route, amneziaRevoke.field = route, field
	amneziaRevoke.Unlock()
}

// amneziaSession signs in with key, trying each way out.
func (a *App) amneziaSession(ctx context.Context, key string) (*amnezia.Client, error) {
	var last error
	for _, hc := range a.amneziaClients() {
		c := amnezia.New(hc, amneziaBase)
		amneziaRevoke.Lock()
		c.UseRevoke(amneziaRevoke.route, amneziaRevoke.field)
		amneziaRevoke.Unlock()
		err := c.Login(ctx, key)
		if err == nil {
			return c, nil
		}
		var e *amnezia.Error
		if errors.As(err, &e) {
			return nil, err // the account answered: another way changes nothing
		}
		last = err
	}
	return nil, fmt.Errorf("личный кабинет Amnezia недоступен (%v). Он часто заблокирован: включите VPN через другой сервер или возьмите файл локации в кабинете вручную", last)
}

// AmneziaLocations lists the AmneziaWG locations of a key (or of the key
// an Amnezia server was added with, by its id).
func (a *App) AmneziaLocations(key, serverID string) ([]amnezia.Location, error) {
	if serverID != "" {
		srv := a.Settings().ServerByID(serverID)
		if srv == nil || srv.Amnezia == nil {
			return nil, errors.New("это не сервер Amnezia Premium")
		}
		key = srv.Amnezia.Key
	}
	ctx, cancel := context.WithTimeout(a.ctx, 2*amnezia.Timeout)
	defer cancel()
	c, err := a.amneziaSession(ctx, key)
	if err != nil {
		return nil, err
	}
	return c.Locations(ctx, "awg")
}

func amneziaName(loc amnezia.Location) string {
	n := "Amnezia"
	if f := amnezia.Flag(loc.Code); f != "" {
		n += " · " + f
	} else {
		n += " ·"
	}
	return n + " " + loc.Name
}

// amneziaServer gets the file of a location and makes a server of it.
// When all slots are taken and old (the location being replaced) is given,
// old's file is given back first and the new one asked again.
func (a *App) amneziaServer(ctx context.Context, c *amnezia.Client, ref settings.AmneziaRef, loc amnezia.Location, old string) (*settings.Server, bool, error) {
	revoked := false
	conf, err := c.Config(ctx, loc.Code, ref.UserCountry)
	var e *amnezia.Error
	if err != nil && old != "" && errors.As(err, &e) && (e.Code == "CONFIG_LIMIT" || e.Code == "MAX_DEVICES_REACHED") {
		if rerr := c.Revoke(ctx, old); rerr == nil {
			rememberRevoke(c)
			revoked = true
			conf, err = c.Config(ctx, loc.Code, ref.UserCountry)
		}
	}
	if err != nil {
		return nil, revoked, err
	}
	srv, err := importer.AWGServer(conf, amneziaName(loc), "Amnezia Premium")
	if err != nil {
		return nil, revoked, fmt.Errorf("файл локации %s не прочитался: %v", loc.Name, err)
	}
	ref.Country, ref.CountryName = loc.Code, loc.Name
	srv.Amnezia = &ref
	srv.Info += " · Amnezia Premium"
	return srv, revoked, nil
}

func findLocation(locs []amnezia.Location, code string) (amnezia.Location, bool) {
	for _, l := range locs {
		if strings.EqualFold(l.Code, code) {
			return l, true
		}
	}
	return amnezia.Location{}, false
}

// AmneziaAdd adds the location country of a Premium key as a server. If a
// server with this key is already there, its location changes instead.
func (a *App) AmneziaAdd(k importer.AmneziaKey, country string) (string, string, error) {
	for _, srv := range a.Settings().Servers {
		if srv.Amnezia != nil && srv.Amnezia.Key == strings.TrimSpace(k.Key) {
			return a.AmneziaSwitch(srv.ID, country)
		}
	}
	ctx, cancel := context.WithTimeout(a.ctx, 4*amnezia.Timeout)
	defer cancel()
	c, err := a.amneziaSession(ctx, k.Key)
	if err != nil {
		return "", "", err
	}
	locs, err := c.Locations(ctx, "awg")
	if err != nil {
		return "", "", err
	}
	loc, ok := findLocation(locs, country)
	if !ok {
		return "", "", fmt.Errorf("локации %q нет в подписке", country)
	}
	ref := settings.AmneziaRef{Key: strings.TrimSpace(k.Key), UserCountry: k.UserCountry}
	srv, _, err := a.amneziaServer(ctx, c, ref, loc, "")
	if err != nil {
		return "", "", err
	}
	logx.Infof("Amnezia Premium: добавлена локация %s (%s)", loc.Name, loc.Code)
	if _, err := a.AddItems([]importer.Item{{Server: srv}}); err != nil {
		return "", "", err
	}
	return srv.Name, "", nil
}

// AmneziaSwitch moves an Amnezia server to another location: the new file
// first (the old one keeps working if that fails), then the old file goes
// back to the account. The note says what the user still has to do.
func (a *App) AmneziaSwitch(id, country string) (string, string, error) {
	cur := a.Settings().ServerByID(id)
	if cur == nil || cur.Amnezia == nil {
		return "", "", errors.New("это не сервер Amnezia Premium")
	}
	ref := *cur.Amnezia
	if strings.EqualFold(ref.Country, country) {
		return cur.Name, "", nil
	}
	ctx, cancel := context.WithTimeout(a.ctx, 5*amnezia.Timeout)
	defer cancel()
	c, err := a.amneziaSession(ctx, ref.Key)
	if err != nil {
		return "", "", err
	}
	locs, err := c.Locations(ctx, "awg")
	if err != nil {
		return "", "", err
	}
	loc, ok := findLocation(locs, country)
	if !ok {
		return "", "", fmt.Errorf("локации %q нет в подписке", country)
	}
	srv, revoked, err := a.amneziaServer(ctx, c, ref, loc, ref.Country)
	if err != nil {
		return "", "", err
	}
	oldName := ref.CountryName
	if oldName == "" {
		oldName = strings.ToUpper(ref.Country)
	}
	err = a.update(func(s *settings.Settings) error {
		for i := range s.Servers {
			if s.Servers[i].ID != id {
				continue
			}
			o := s.Servers[i]
			name := srv.Name
			if !strings.HasPrefix(o.Name, "Amnezia ·") { // renamed by the user: keep it
				name = o.Name
			}
			srv.ID, srv.Enabled, srv.Added, srv.Name = o.ID, o.Enabled, o.Added, name
			srv.Proxy["name"] = name
			s.Servers[i] = *srv
			return nil
		}
		return errors.New("сервер не найден")
	})
	if err != nil {
		return "", "", err
	}
	logx.Infof("Amnezia Premium: локация %s → %s", oldName, loc.Name)
	a.afterServersChanged()
	if revoked {
		return srv.Name, "", nil
	}
	rerr := c.Revoke(ctx, ref.Country)
	rememberRevoke(c)
	if rerr != nil {
		if errors.Is(rerr, amnezia.ErrNoRevoke) && len(c.Routes) > 0 {
			logx.Warnf("Amnezia Premium: не нашёл, как кабинет отзывает файл; вызовы страницы: %s", strings.Join(c.Routes, " "))
		} else {
			logx.Warnf("Amnezia Premium: файл локации %s не отозван: %v", oldName, rerr)
		}
		return srv.Name, "Файл прежней локации (" + oldName + ") ещё занимает подключение: отзовите его в личном кабинете Amnezia — «Файлы конфигурации», ⋮ у локации, «Отозвать».", nil
	}
	logx.Infof("Amnezia Premium: файл локации %s отозван", oldName)
	return srv.Name, "", nil
}

// amneziaForget gives the file of a deleted Amnezia server back, so that
// the slot is free again. Best effort, in the background.
func (a *App) amneziaForget(ref settings.AmneziaRef) {
	ctx, cancel := context.WithTimeout(a.ctx, 3*amnezia.Timeout)
	defer cancel()
	c, err := a.amneziaSession(ctx, ref.Key)
	if err == nil {
		err = c.Revoke(ctx, ref.Country)
		rememberRevoke(c)
	}
	if err != nil {
		logx.Warnf("Amnezia Premium: файл удалённой локации %s не отозван (%v) — отзовите его в личном кабинете, чтобы освободить подключение", ref.CountryName, err)
		return
	}
	logx.Infof("Amnezia Premium: файл удалённой локации %s отозван", ref.CountryName)
}
