package ir

import (
	"strings"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/job"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

func (x *IR) allImageSites() []*ImageSite {
	x.once(SummaryImageSite, func() {
		var out []*ImageSite
		add := func(s *ImageSite) {
			if s != nil {
				out = append(out, s)
			}
		}
		if w := x.workflow; w != nil {
			for _, je := range w.Jobs.Value.Entries {
				if je.Value.Status != workflow.Present {
					continue
				}
				j := je.Value.Value
				if j.Container.Status == workflow.Present {
					add(x.containerSite(j, j.Container.Value, analysis.ImageSiteKindContainer, ""))
				}
				if j.Services.Status == workflow.Dynamic && j.Services.Expr != nil {
					e := j.Services.Expr
					add(&ImageSite{key: keyOf(x.paths, x.input, x.tree, e.Base),
						alwaysSkipped: x.alwaysSkipped(e.Base), at: x.handleOf(e.Base), site: analysis.ImageSiteKindService,
						inconclusiveImages: []InconclusiveImage{{Text: e.Text(), Dispatch: job.DispatchInputs(w, *e), At: x.handleOf(e.Base)}}})
				}
				if j.Services.Status == workflow.Present {
					for _, se := range j.Services.Value.Entries {
						if se.Value.Status == workflow.Present {
							add(x.containerSite(j, se.Value.Value, analysis.ImageSiteKindService, se.Key.AsString()))
						}
					}
				}
				for _, s := range j.Steps.Value.Items {
					add(x.dockerStepSite(s.Uses))
				}
			}
		}
		if a := x.action; a != nil {
			for _, s := range a.Runs.Value.Steps.Value.Items {
				add(x.dockerStepSite(s.Uses))
			}
			if img := a.Runs.Value.Image; img.Status == workflow.Present {
				if ref, ok := workflow.DockerImageOf(img.Value); ok {
					s := &ImageSite{key: keyOf(x.paths, x.input, x.tree, img.Value.Base),
						alwaysSkipped: x.alwaysSkipped(img.Value.Base), at: x.handleOf(img.Value.Base), site: analysis.ImageSiteKindAction}
					s.images = x.appendImage(s.images, ref, img.Value, img.Value.Text()[len("docker://"):], false)
					add(s)
				}
			}
		}
		x.imageSites = out
	})
	return x.imageSites
}

// containerSite is the summary of c, the container or the service named
// service of the job j: the image written, the values of the matrix a
// whole ${{ matrix.<name> }} takes, or an image not read. A container
// without an image is none.
func (x *IR) containerSite(j workflow.Job, c workflow.Container, kind analysis.ImageSiteKind, service string) *ImageSite {
	if c.Image.Status != workflow.Present {
		return nil
	}
	img := c.Image.Value
	s := &ImageSite{key: keyOf(x.paths, x.input, x.tree, c.Base),
		alwaysSkipped: x.alwaysSkipped(c.Base), at: x.handleOf(img.Base), site: kind, serviceName: service}
	if img.Parts == nil {
		if ref, ok := workflow.ImageReferenceOf(img); ok {
			s.images = x.appendImage(s.images, ref, img, img.Text(), false)
		}
		return s
	}
	vals, ok := job.MatrixValues(j, img)
	if !ok {
		s.inconclusiveImages = append(s.inconclusiveImages, InconclusiveImage{Text: img.Text(), Dispatch: job.DispatchInputs(x.workflow, img), At: x.handleOf(img.Base)})
		return s
	}
	for _, v := range vals {
		if v.Parts != nil {
			s.inconclusiveImages = append(s.inconclusiveImages, InconclusiveImage{Text: v.Text(), Dispatch: job.DispatchInputs(x.workflow, v), At: x.handleOf(v.Base)})
			continue
		}
		if ref, ok := workflow.ImageReferenceOf(v); ok {
			s.images = x.appendImage(s.images, ref, v, v.Text(), true)
		}
	}
	return s
}

// dockerStepSite is the summary of a step's uses: docker://, or nil.
func (x *IR) dockerStepSite(fu workflow.Field[workflow.Uses]) *ImageSite {
	if fu.Status != workflow.Present {
		return nil
	}
	u := fu.Value
	kind := u.Kind
	if kind == workflow.UsesFolded {
		kind = u.Folded
	}
	if kind != workflow.UsesDocker {
		return nil
	}
	s := &ImageSite{key: keyOf(x.paths, x.input, x.tree, u.Base),
		alwaysSkipped: x.alwaysSkipped(u.Base), at: x.handleOf(u.Base), site: analysis.ImageSiteKindStep}
	ref := workflow.ImageReference{Name: u.Image, Tag: u.Tag, Digest: u.Digest}
	s.images = x.appendImage(s.images, ref, u.String, strings.TrimPrefix(u.AsString(), "docker://"), false)
	return s
}

// appendImage appends the image ref, written as text in s, to imgs. An
// image with a digest docker refuses is not pulled, so it runs nothing
// and is not appended.
func (x *IR) appendImage(imgs []Image, ref workflow.ImageReference, s workflow.String, text string, matrix bool) []Image {
	return appendImageAt(imgs, ref, text, matrix, x.handleOf(s.Base))
}

// appendImageAt appends the image ref, written as text at the handle at, to
// imgs, as appendImage does: in a file of the inputs or in the value of a
// fact (an action of another repository).
func appendImageAt(imgs []Image, ref workflow.ImageReference, text string, matrix bool, at Handle) []Image {
	if ref.Digest.Text != "" && !ref.Pinned() {
		return imgs
	}
	return append(imgs, Image{Text: text, Tag: ref.Tag.Text, Pinned: ref.Pinned(), Matrix: matrix, At: at})
}
