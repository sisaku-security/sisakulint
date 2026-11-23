package analysis

import (
	"encoding/json"
	"errors"
)

// ImageSiteKind is where an image to run is written.
type ImageSiteKind uint8

const (
	ImageSiteKindUnset     ImageSiteKind = iota
	ImageSiteKindContainer               // a job's container
	ImageSiteKindService                 // a service of a job
	ImageSiteKindStep                    // a step's uses: docker://
	ImageSiteKindAction                  // an action.yml's runs.image: docker://
)

// imageSiteKindNames are the values of $defs/image-site-kind of the schema
// of findings (actions/rules/schema/findings-v0.json), which the args of
// findings hold.
var imageSiteKindNames = [...]string{"ImageSiteKindUnset", "container", "service", "step", "action"}

func (k ImageSiteKind) String() string { return imageSiteKindNames[k] }

// MarshalJSON writes k as the schema of findings names it
// (findings-v0.json, $defs/image-site-kind); ImageSiteKindUnset has no name
// there.
func (k ImageSiteKind) MarshalJSON() ([]byte, error) {
	if k == ImageSiteKindUnset {
		return nil, errors.New("ImageSiteKindUnset is no site")
	}
	return json.Marshal(k.String())
}
