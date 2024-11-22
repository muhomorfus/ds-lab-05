package main

import (
	"context"
	"fmt"
	"github.com/kelseyhightower/envconfig"
	"github.com/labstack/echo/v4"
	_ "github.com/lib/pq"
	"github.com/muhomorfus/ds-lab-02/services/auth/jwt"
	"github.com/muhomorfus/ds-lab-02/services/gateway/internal/clients/library"
	"github.com/muhomorfus/ds-lab-02/services/gateway/internal/clients/rating"
	"github.com/muhomorfus/ds-lab-02/services/gateway/internal/clients/reservation"
	"github.com/muhomorfus/ds-lab-02/services/gateway/internal/generated"
	"github.com/muhomorfus/ds-lab-02/services/gateway/internal/openapi"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if err := run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run() error {
	var cfg config
	if err := envconfig.Process("", &cfg); err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	libraryClient, err := library.NewClientWithResponses(cfg.LibraryAddress, library.WithHTTPClient(httpClient()))
	if err != nil {
		return fmt.Errorf("create library client: %w", err)
	}

	ratingClient, err := rating.NewClientWithResponses(cfg.RatingAddress, rating.WithHTTPClient(httpClient()))
	if err != nil {
		return fmt.Errorf("create rating client: %w", err)
	}

	reservationClient, err := reservation.NewClientWithResponses(cfg.ReservationAddress, reservation.WithHTTPClient(httpClient()))
	if err != nil {
		return fmt.Errorf("create reservation client: %w", err)
	}

	server := openapi.New(libraryClient, reservationClient, ratingClient)
	router := echo.New()
	router.Use(jwt.Middleware(cfg.JWKsURI))

	slog.Info("using jwks uri", "uri", cfg.JWKsURI)

	generated.RegisterHandlers(router, generated.NewStrictHandler(server, nil))

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	go func() {
		<-ctx.Done()

		_ = router.Close()
	}()

	if err := router.Start(cfg.listerAddress()); err != nil {
		return fmt.Errorf("listen http server: %w", err)
	}

	return nil
}

func httpClient() *http.Client {
	return &http.Client{}
}

type config struct {
	LibraryAddress     string `envconfig:"LIBRARY_ADDRESS" required:"true"`
	RatingAddress      string `envconfig:"RATING_ADDRESS" required:"true"`
	ReservationAddress string `envconfig:"RESERVATION_ADDRESS" required:"true"`
	Port               string `envconfig:"PORT" required:"true"`
	JWKsURI            string `envconfig:"JWKS_URI" required:"true"`
}

func (c config) listerAddress() string {
	return fmt.Sprintf("0.0.0.0:%s", c.Port)
}
