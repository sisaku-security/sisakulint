package workflow

// Container is a job's container or one of its services: the image to run,
// the credentials of its registry, and its env. Written as a string, it is
// the image alone.
type Container struct {
	Base
	Image    Field[String]
	Username Field[String] // credentials.username
	Password Field[String] // credentials.password; Dynamic when credentials is a ${{ }}
	Env      Field[Map[String]]
}

// container reads the value of e, a string or a mapping (container,
// services-container). ports, volumes, options, command and entrypoint
// are not read: no rule reads them.
func (r *reader) container(e *entry, p pos) Field[Container] {
	if e == nil {
		return Field[Container]{}
	}
	if _, ok := r.peek(e.value).Mapping(); !ok {
		s := r.str(e, p)
		f := Field[Container]{Status: s.Status, Key: s.Key, Expr: s.Expr}
		f.Value = Container{Base: s.Value.Base, Image: s}
		return f
	}
	v, ents := r.object(e, p)
	f := field[Container](e, v)
	if v.st != Present {
		return f
	}
	c := Container{Base: Base{Node: v.n, Via: v.p.via}, Image: r.str(get(ents, "image"), v.p), Env: r.strMap(get(ents, "env"), v.p)}
	if cr := get(ents, "credentials"); cr != nil {
		cv, cents := r.object(cr, v.p)
		switch cv.st {
		case Present:
			c.Username = r.str(get(cents, "username"), cv.p)
			c.Password = r.str(get(cents, "password"), cv.p)
		case Dynamic: // the password is somewhere in the ${{ }}
			c.Password = field[String](cr, cv)
		}
	}
	f.Value = c
	return f
}

// services reads the services of a job: a mapping of names to containers.
func (r *reader) services(e *entry, p pos) Field[Map[Container]] {
	return readMap(r, e, p, r.container)
}
