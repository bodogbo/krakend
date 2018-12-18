// Package mux provides some basic implementations for building routers based on net/http mux
package mux

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/devopsfaith/krakend/config"
	"github.com/devopsfaith/krakend/logging"
	"github.com/devopsfaith/krakend/proxy"
	"github.com/devopsfaith/krakend/router"
)

// DefaultDebugPattern is the default pattern used to define the debug endpoint
const DefaultDebugPattern = "/__debug/"

// RunServerFunc is a func that will run the http Server with the given params.
type RunServerFunc func(context.Context, config.ServiceConfig, http.Handler) error

// Config is the struct that collects the parts the router should be builded from
type Config struct {
	Engine         Engine
	Middlewares    []HandlerMiddleware
	HandlerFactory HandlerFactory
	ProxyFactory   proxy.Factory
	Logger         logging.Logger
	DebugPattern   string
	RunServer      RunServerFunc
}

// HandlerMiddleware is the interface for the decorators over the http.Handler
type HandlerMiddleware interface {
	Handler(h http.Handler) http.Handler
}

// DefaultFactory returns a net/http mux router factory with the injected proxy factory and logger
func DefaultFactory(pf proxy.Factory, logger logging.Logger) router.Factory {
	return factory{
		Config{
			Engine:         DefaultEngine(),
			Middlewares:    []HandlerMiddleware{},
			HandlerFactory: EndpointHandler,
			ProxyFactory:   pf,
			Logger:         logger,
			DebugPattern:   DefaultDebugPattern,
			RunServer:      router.RunServer,
		},
	}
}

// NewFactory returns a net/http mux router factory with the injected configuration
func NewFactory(cfg Config) router.Factory {
	if cfg.DebugPattern == "" {
		cfg.DebugPattern = DefaultDebugPattern
	}
	return factory{cfg}
}

type factory struct {
	cfg Config
}

// New implements the factory interface
func (rf factory) New() router.Router {
	return rf.NewWithContext(context.Background())
}

// NewWithContext implements the factory interface
func (rf factory) NewWithContext(ctx context.Context) router.Router {
	return httpRouter{rf.cfg, ctx, rf.cfg.RunServer}
}

type httpRouter struct {
	cfg       Config
	ctx       context.Context
	RunServer RunServerFunc
}

// Run implements the router interface
func (r httpRouter) Run(cfg config.ServiceConfig) {
	if cfg.Debug {
		r.cfg.Engine.Handle(r.cfg.DebugPattern, DebugHandler(r.cfg.Logger))
	}

	router.InitHTTPDefaultTransport(cfg)

	r.registerKrakendEndpoints(cfg.Endpoints)

	if err := r.RunServer(r.ctx, cfg, r.handler()); err != nil {
		r.cfg.Logger.Error(err.Error())
	}

	r.cfg.Logger.Info("Router execution ended")
}

func (r httpRouter) registerKrakendEndpoints(endpoints []*config.EndpointConfig) {
	uniquePaths := map[string]map[string]http.HandlerFunc{}
	sortedUniquePaths := []string{}
	for _, c := range endpoints {
		proxyStack, err := r.cfg.ProxyFactory.New(c)
		if err != nil {
			r.cfg.Logger.Error("calling the ProxyFactory", err.Error())
			continue
		}

		handler := r.cfg.HandlerFactory(c, proxyStack)
		method := strings.ToTitle(c.Method)

		if err := r.checkKrakendEndpoint(method, c.Endpoint, len(c.Backend)); err != nil {
			r.cfg.Logger.Error("validating endpoint:", err.Error())
			continue
		}

		if _, ok := uniquePaths[c.Endpoint]; !ok {
			uniquePaths[c.Endpoint] = map[string]http.HandlerFunc{}
			sortedUniquePaths = append(sortedUniquePaths, c.Endpoint)
		}
		uniquePaths[c.Endpoint][method] = handler
	}

	for _, path := range sortedUniquePaths {
		r.cfg.Engine.Handle(path, methodDispatcher(uniquePaths[path]))
	}
}

func (r httpRouter) checkKrakendEndpoint(method, path string, totBackends int) error {
	method = strings.ToTitle(method)
	if method != http.MethodGet && totBackends > 1 {
		return fmt.Errorf("%s endpoints must have a single backend! Ignoring %s", method, path)
	}

	switch method {
	case http.MethodGet:
	case http.MethodPost:
	case http.MethodPut:
	case http.MethodPatch:
	case http.MethodDelete:
	default:
		return fmt.Errorf("Unsupported method %s", method)
	}

	r.cfg.Logger.Debug("registering the endpoint", method, path)
	return nil
}

func (r httpRouter) handler() http.Handler {
	var handler http.Handler = r.cfg.Engine
	for _, middleware := range r.cfg.Middlewares {
		r.cfg.Logger.Debug("Adding the middleware", middleware)
		handler = middleware.Handler(handler)
	}
	return handler
}

func methodDispatcher(handlers map[string]http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if handler, ok := handlers[req.Method]; ok {
			handler(rw, req)
			return
		}

		rw.Header().Set(router.CompleteResponseHeaderName, router.HeaderIncompleteResponseValue)
		http.Error(rw, "", http.StatusMethodNotAllowed)
	})
}
