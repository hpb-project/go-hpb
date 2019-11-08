package types

import "fmt"

type Querier = func (path []string) (res []byte, err error)

// QueryRouter provides queryables for each query path.
type QRouter interface {
	AddRoute(r string, q Querier) (rq QRouter)
	Route(path string) (q Querier)
}

type qRouter struct {
	handlers map[string]Querier
}

func NewQRouter() *qRouter {
	return &qRouter{handlers: map[string]Querier{}}
}

func (this *qRouter) AddRoute(path string, q Querier) QRouter {
	if _,ok := this.handlers[path]; ok {
		panic(fmt.Sprintf("route %s has already been initialized", path))
	}

	this.handlers[path] = q
	return this
}

func (this *qRouter) Route(path string) Querier {
	rq, exist := this.handlers[path]
	if !exist {
		return nil
	}else {
		return rq
	}
}

