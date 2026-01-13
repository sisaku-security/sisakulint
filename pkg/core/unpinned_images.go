package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

type DockerImageRef struct {
	Raw          string
	Registry     string
	Namespace    string
	Repository   string
	Tag          string
	Digest       string
	IsExpression bool
}

func ParseDockerImageRef(ref string) *DockerImageRef {
	result := &DockerImageRef{
		Raw: ref,
	}

	if strings.Contains(ref, "${{") {
		result.IsExpression = true
		return result
	}

	digestParts := strings.SplitN(ref, "@", 2)
	imageWithTag := digestParts[0]
	if len(digestParts) == 2 {
		result.Digest = strings.TrimPrefix(digestParts[1], "sha256:")
	}

	parts := strings.Split(imageWithTag, "/")

	if len(parts) == 1 {
		result.Repository, result.Tag = splitRepositoryTag(parts[0])
		return result
	}

	firstPart := parts[0]
	if isRegistry(firstPart) {
		result.Registry = firstPart
		if len(parts) == 2 {
			result.Repository, result.Tag = splitRepositoryTag(parts[1])
		} else {
			result.Namespace = strings.Join(parts[1:len(parts)-1], "/")
			result.Repository, result.Tag = splitRepositoryTag(parts[len(parts)-1])
		}
	} else {
		result.Namespace = strings.Join(parts[:len(parts)-1], "/")
		result.Repository, result.Tag = splitRepositoryTag(parts[len(parts)-1])
	}

	return result
}

func splitRepositoryTag(s string) (string, string) {
	idx := strings.LastIndex(s, ":")
	if idx == -1 {
		return s, ""
	}
	return s[:idx], s[idx+1:]
}

func isRegistry(s string) bool {
	if strings.Contains(s, ".") {
		return true
	}
	if s == "localhost" || strings.HasPrefix(s, "localhost:") {
		return true
	}
	if idx := strings.Index(s, ":"); idx != -1 {
		port := s[idx+1:]
		if isNumeric(port) {
			return true
		}
	}
	return false
}

func isNumeric(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func (d *DockerImageRef) IsPinned() bool {
	return d.Digest != ""
}

func (d *DockerImageRef) IsLatestTag() bool {
	return d.Tag == "latest" || (d.Tag == "" && d.Digest == "")
}

func (d *DockerImageRef) HasTag() bool {
	return d.Tag != ""
}

type ImagePinStatus int

const (
	ImagePinStatusPinned ImagePinStatus = iota
	ImagePinStatusLatest
	ImagePinStatusTagOnly
	ImagePinStatusExpression
)

func (d *DockerImageRef) GetPinStatus() ImagePinStatus {
	if d.IsExpression {
		return ImagePinStatusExpression
	}
	if d.IsPinned() {
		return ImagePinStatusPinned
	}
	if d.IsLatestTag() {
		return ImagePinStatusLatest
	}
	return ImagePinStatusTagOnly
}

type UnpinnedImagesRule struct {
	BaseRule
}

func NewUnpinnedImagesRule() *UnpinnedImagesRule {
	return &UnpinnedImagesRule{
		BaseRule: BaseRule{
			RuleName: "unpinned-images",
			RuleDesc: "Warn if container images are not pinned by SHA256 digest.",
		},
	}
}

func (rule *UnpinnedImagesRule) VisitJobPre(node *ast.Job) error {
	if node.Container != nil && node.Container.Image != nil {
		rule.checkImage(node.Container.Image, "container", node.ID)
	}

	for serviceName, service := range node.Services {
		if service.Container != nil && service.Container.Image != nil {
			rule.checkImage(service.Container.Image, "service "+serviceName, node.ID)
		}
	}

	return nil
}

func (rule *UnpinnedImagesRule) checkImage(image *ast.String, context string, jobID *ast.String) {
	if image == nil || image.Value == "" {
		return
	}

	ref := ParseDockerImageRef(image.Value)
	status := ref.GetPinStatus()

	switch status {
	case ImagePinStatusPinned:
		return
	case ImagePinStatusLatest:
		rule.Errorf(image.Pos,
			"container image '%s' in %s of job '%s' is using 'latest' tag or no tag, which is mutable and poses a supply chain risk. Pin the image using SHA256 digest (e.g., image:tag@sha256:...).",
			image.Value, context, jobID.Value)
	case ImagePinStatusTagOnly:
		rule.Errorf(image.Pos,
			"container image '%s' in %s of job '%s' is using a tag without SHA256 digest. Tags are mutable and can be overwritten. Consider pinning with SHA256 digest (e.g., %s@sha256:...).",
			image.Value, context, jobID.Value, image.Value)
	case ImagePinStatusExpression:
		rule.checkExpressionImage(image, context, jobID)
	}
}

func (rule *UnpinnedImagesRule) checkExpressionImage(image *ast.String, context string, jobID *ast.String) {
	if strings.Contains(image.Value, "matrix.") {
		rule.Errorf(image.Pos,
			"container image '%s' in %s of job '%s' is specified using a matrix variable. Ensure all matrix values are pinned by SHA256 digest for supply chain security.",
			image.Value, context, jobID.Value)
		return
	}

	rule.Errorf(image.Pos,
		"container image '%s' in %s of job '%s' is specified using an expression. Unable to verify if the image is pinned by SHA256 digest. Consider using a literal image reference with SHA256 digest for supply chain security.",
		image.Value, context, jobID.Value)
}
