package workflow

// On is the events that trigger the workflow (on-strict), in the order
// written, whichever of its three forms it has.
type On struct {
	Base
	Events []Event
}

// Event returns the event named name, compared exactly like the schema's
// keys. An event whose name GitHub does not take is none of them.
func (o On) Event(name EventName) (Event, bool) {
	for _, e := range o.Events {
		if n, err := ParseEventName(e.Name.AsString()); err == nil && n == name {
			return e, true
		}
	}
	return Event{}, false
}

// Event is one event. Base is its value in the mapping form (null, a
// mapping, or the sequence of schedule), and its name otherwise.
type Event struct {
	Base
	Name    String
	Types   Field[List[String]]
	Filters []Filter           // branches, paths-ignore, workflows and the like, in order
	Inputs  Field[Map[Input]]  // workflow_dispatch, workflow_call
	Secrets Field[Map[Secret]] // workflow_call
	Outputs Field[Map[Output]] // workflow_call
}

// Filter is a key of an event that lists patterns or names.
type Filter struct {
	Key    String
	Values Field[List[String]]
}

// Input is an input of workflow_dispatch or workflow_call.
type Input struct {
	Base
	Type     Field[String]
	Required Field[String]
	Default  Field[String]
	Options  Field[List[String]]
}

// Secret is a secret of workflow_call.
type Secret struct {
	Base
	Required Field[String]
}

// Output is an output of workflow_call.
type Output struct {
	Base
	Value Field[String]
}

// readOn reads the three forms of on. Its definition is the runner's
// on-new (schema_gen.go): event names are checked, and what is in an event
// is read loosely, as GitHub does.
func (r *reader) readOn(e *entry, p pos) Field[On] {
	if e == nil {
		return Field[On]{}
	}
	v := r.value(e.value, p, e.def)
	f := field[On](e, v)
	f.Value.Base = Base{Node: v.n, Via: v.p.via}
	if v.st != Present {
		return f
	}
	if v.kind != valMapping {
		names, ok := r.list(v, e.def)
		if !ok {
			f.Status = Invalid
		}
		for _, s := range names.Items {
			f.Value.Events = append(f.Value.Events, Event{Base: s.Base, Name: s})
		}
		return f
	}
	ents, _, _ := r.mapping(v, e.def)
	for i := range ents {
		if !ents[i].dup {
			f.Value.Events = append(f.Value.Events, r.event(&ents[i], v.p))
		}
	}
	return f
}

func (r *reader) event(e *entry, p pos) Event {
	ev := Event{Name: e.key}
	v := r.value(e.value, p, e.def)
	ev.Base = Base{Node: v.n, Via: v.p.via}
	if v.st != Present || v.kind != valMapping {
		return ev
	}
	ents, _, _ := r.mapping(v, e.def)
	for i := range ents {
		k := &ents[i]
		if k.dup || !k.prop {
			continue
		}
		switch k.name {
		case "types":
			ev.Types = r.strList(k, v.p)
		case "inputs":
			ev.Inputs = readMap(r, k, v.p, r.input)
		case "secrets":
			ev.Secrets = readMap(r, k, v.p, r.secret)
		case "outputs":
			ev.Outputs = readMap(r, k, v.p, r.output)
		default:
			ev.Filters = append(ev.Filters, Filter{Key: k.key, Values: r.strList(k, v.p)})
		}
	}
	return ev
}

// object reads the value of e as a mapping of properties; it is Present
// with no entries for a null the schema allows in its place.
func (r *reader) object(e *entry, p pos) (val, []entry) {
	v := r.value(e.value, p, e.def)
	if v.st != Present || v.kind != valMapping {
		return v, nil
	}
	ents, _, _ := r.mapping(v, e.def)
	return v, ents
}

func (r *reader) input(e *entry, p pos) Field[Input] {
	v, ents := r.object(e, p)
	f := field[Input](e, v)
	f.Value = Input{
		Base:     Base{Node: v.n, Via: v.p.via},
		Type:     r.str(get(ents, "type"), v.p),
		Required: r.str(get(ents, "required"), v.p),
		Default:  r.str(get(ents, "default"), v.p),
		Options:  r.strList(getAny(ents, "options"), v.p), // a loose key of workflow-dispatch-input-mapping-relaxed
	}
	return f
}

func (r *reader) secret(e *entry, p pos) Field[Secret] {
	v, ents := r.object(e, p)
	f := field[Secret](e, v)
	f.Value = Secret{Base: Base{Node: v.n, Via: v.p.via}, Required: r.str(get(ents, "required"), v.p)}
	return f
}

func (r *reader) output(e *entry, p pos) Field[Output] {
	v, ents := r.object(e, p)
	f := field[Output](e, v)
	f.Value = Output{Base: Base{Node: v.n, Via: v.p.via}, Value: r.str(get(ents, "value"), v.p)}
	return f
}
