package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
	"github.com/unrolled/render"
	"golang.org/x/oauth2"
)

type RenderWrapper struct {
	rnd *render.Render
}

func (r *RenderWrapper) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	fmt.Println("name: ", name, "data: ", data)
	return r.rnd.HTML(w, 0, name, data)
}

func main() {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, "http://localhost:5556/dex")
	if err != nil {
		panic(err)
	}

	// environment:
	//   DEX_APP_CLIENT_ID: example-app
	//   DEX_APP_CLIENT_SECRET:
	//   DEX_APP_REDIRECT_URI: http://localhost:4000/callback
	//   DEX_APP_ISSUER_ROOT: http://localhost:5556
	oauth2Config := &oauth2.Config{
		ClientID:     "kiwi-app",
		ClientSecret: "ZXhhbXBsZS1hcHAtc2VjcmV0",
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
		RedirectURL:  "http://localhost:4000/auth/callback",
	}
	idTokenVerifier := provider.Verifier(&oidc.Config{ClientID: "kiwi-app"})

	r := &RenderWrapper{
		render.New(render.Options{
			Directory:  "views",
			Extensions: []string{".html"},
			Layout:     "layout",
		}),
	}

	e := echo.New()
	e.Renderer = r
	e.Logger.SetLevel(log.DEBUG)

	e.GET("/", func(c echo.Context) error {
		return c.Render(http.StatusOK, "auth/login", nil)
	})
	e.GET("/auth/login", func(c echo.Context) error {
		// TODO: state
		state := "state"
		// http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
		return c.Redirect(http.StatusFound, oauth2Config.AuthCodeURL(state))
	})
	e.GET("/auth/callback", func(c echo.Context) error {
		// TODO: state
		// state := r.URL.Query().Get("state")

		// Verify state.

		oauth2Token, err := oauth2Config.Exchange(ctx, c.Request().URL.Query().Get("code"))
		if err != nil {
			panic(err)
		}

		// Extract the ID Token from OAuth2 token.
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			panic("Missing token")
		}

		// Parse and verify ID Token payload.
		idToken, err := idTokenVerifier.Verify(ctx, rawIDToken)
		if err != nil {
			panic(err)
		}

		// Extract custom claims.
		var claims struct {
			Email    string   `json:"email"`
			Verified bool     `json:"email_verified"`
			Groups   []string `json:"groups"`
		}
		if err := idToken.Claims(&claims); err != nil {
			panic(err)
		}
		return c.Redirect(http.StatusFound, "/auth/success")
	})

	go func() {
		if err := e.Start(":4000"); err != nil && err != http.ErrServerClosed {
			e.Logger.Fatal("shutting down the server")
		}
		e.Logger.Info("Bye")
	}()

	// gracefull shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	e.Logger.Info("Shutting down..")
	if err := e.Shutdown(ctx); err != nil {
		e.Logger.Fatal(err)
	}
}
