package web

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/PopinjayJohn/vtt-semiplane/internal/httpapi"
	"github.com/a-h/templ"
)

// Renderer is the httpapi.Renderer this package provides.
//
// It is the whole of the boundary between the two packages: the router decides
// what a request is allowed to see and hands the result over as a view model,
// and this type decides what the response looks like. Neither imports the
// other's internals, and neither can grow a permission check, because this one
// has no database, no session and no policy to check anything against.
type Renderer struct{}

// NewRenderer returns the renderer.
func NewRenderer() *Renderer { return &Renderer{} }

// Document writes a whole HTML page.
func (r *Renderer) Document(w http.ResponseWriter, req *http.Request, v httpapi.View) error {
	shell, err := shellOf(v)
	if err != nil {
		return err
	}
	body, err := regionOf(v)
	if err != nil {
		return err
	}
	return Layout(Doc{Title: shell.Title, Shell: shell, Body: body}).Render(req.Context(), w)
}

// Fragment writes only the content region.
//
// The bytes are what Layout puts inside #page-region and nothing else, which is
// what makes "the fragment is a strict subset of the document" checkable: the
// same component, the same view model, the same escaping, minus the shell. It
// is also what lets a later phase's live-push path re-render under a
// subscriber's own principal and swap the result into the reader's page without
// the client having to know anything about authorization.
func (r *Renderer) Fragment(w http.ResponseWriter, req *http.Request, v httpapi.View) error {
	body, err := regionOf(v)
	if err != nil {
		return err
	}
	return Region(v, body).Render(req.Context(), w)
}

// Region is the swappable element itself.
//
// It is a separate component from the one Document nests inside the layout, so
// that the fragment has the same id and the same tabindex the document's copy
// has: a morph that replaced the region with a differently-identified element
// would work once and then fail, because the next response would look for an id
// that is no longer in the document.
func Region(v httpapi.View, body templ.Component) templ.Component {
	return RegionView(RegionDoc{Shell: mustShell(v), Body: body})
}

// shellOf is the layout's half of a view model.
func shellOf(v httpapi.View) (httpapi.Shell, error) {
	if v == nil {
		return httpapi.Shell{}, errors.New("web: no view model was given to render")
	}
	return v.ViewShell(), nil
}

// mustShell is shellOf for the fragment path, where a view model that is not
// one of ours is a programming error rather than a request to report.
//
// The rendered result is still an escaped, empty region rather than a panic: a
// view model this package does not recognise is a mistake, and a mistake should
// not be able to take the process down from a request path.
func mustShell(v httpapi.View) httpapi.Shell {
	shell, err := shellOf(v)
	if err != nil {
		return httpapi.Shell{}
	}
	return shell
}

// regionOf is the type switch, once, so that Document and Fragment cannot
// disagree about what a view model looks like.
func regionOf(v httpapi.View) (templ.Component, error) {
	switch t := v.(type) {
	case httpapi.HomeView:
		return Home(t), nil
	case httpapi.PageView:
		return Page(t), nil
	case httpapi.SearchView:
		return Search(t), nil
	case httpapi.LoginView:
		return Login(t), nil
	case httpapi.SetupView:
		return Setup(t), nil
	case httpapi.InviteView:
		return Invite(t), nil
	case httpapi.ErrorView:
		return ErrorPage(t), nil
	case nil:
		return nil, errors.New("web: no view model was given to render")
	default:
		return nil, fmt.Errorf("web: this view model has no template: %T", v)
	}
}
