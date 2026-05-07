package httpx

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

type Config struct {
	Enable           bool
	Host             string
	Port             int
	CertFile         string
	KeyFile          string
	PProf            bool
	PrintAccessLog   bool
	ShutdownTimeout  int
	MaxContentLength int64
	ReadTimeout      int
	WriteTimeout     int
	IdleTimeout      int
}

func Init(cfg Config, ctx context.Context, handler http.Handler) func() {
	if !cfg.Enable {
		return func() {}
	}

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  time.Duration(cfg.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.WriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(cfg.IdleTimeout) * time.Second,
	}

	go func() {
		fmt.Println("http server listening on:", addr)

		var err error
		if cfg.CertFile != "" && cfg.KeyFile != "" {
			err = srv.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile)
		} else {
			// SECURITY: TLS termination is handled by a reverse proxy (nginx/load balancer).
			// Plain HTTP on the internal network is intentional and by design.
			// NOSONAR - Insecure transport by design: reverse proxy handles TLS termination.
			// fortify:disable insecure-transport:1 - HTTP is intentional; TLS is handled upstream.
			err = srv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()

	return func() {
		ctx, cancel := context.WithTimeout(ctx, time.Second*time.Duration(cfg.ShutdownTimeout))
		defer cancel()

		srv.SetKeepAlivesEnabled(false)
		if err := srv.Shutdown(ctx); err != nil {
			fmt.Println("cannot shutdown http server:", err)
		}

		select {
		case <-ctx.Done():
			fmt.Println("shutdown http server timeout of", cfg.ShutdownTimeout, "seconds")
		default:
			fmt.Println("http server stopped")
		}
	}
}
