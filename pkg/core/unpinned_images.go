package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// DockerImageRef represents a parsed Docker image reference.
// Format: [registry/][namespace/]repository[:tag][@sha256:digest]
type DockerImageRef struct {
	// Raw is the original image reference string.
	Raw string
	// Registry is the container registry (e.g., "ghcr.io", "docker.io").
	Registry string
	// Namespace is the namespace/organization (e.g., "library", "myorg").
	Namespace string
	// Repository is the image repository name.
	Repository string
	// Tag is the image tag (e.g., "latest", "v1.0.0").
	Tag string
	// Digest is the SHA256 digest (without the "sha256:" prefix).
	Digest string
	// IsExpression indicates if the image reference contains ${{ }} expressions.
	IsExpression bool
}

// ParseDockerImageRef parses a Docker image reference string.
// Examples:
//   - node:18 -> {Repository: "node", Tag: "18"}
//   - node:18@sha256:abc123 -> {Repository: "node", Tag: "18", Digest: "abc123"}
//   - ghcr.io/myorg/myimage:v1.0.0 -> {Registry: "ghcr.io", Namespace: "myorg", Repository: "myimage", Tag: "v1.0.0"}
//   - ${{ matrix.image }} -> {Raw: "${{ matrix.image }}", IsExpression: true}
func ParseDockerImageRef(ref string) *DockerImageRef {
	result := &DockerImageRef{
		Raw: ref,
	}

	// Check if it's an expression
	if strings.Contains(ref, "${{") {
		result.IsExpression = true
		return result
	}

	// Split digest from the rest
	digestParts := strings.SplitN(ref, "@", 2)
	imageWithTag := digestParts[0]
	if len(digestParts) == 2 {
		digest := digestParts[1]
		// Remove "sha256:" prefix if present
		if strings.HasPrefix(digest, "sha256:") {
			result.Digest = strings.TrimPrefix(digest, "sha256:")
		} else {
			result.Digest = digest
		}
	}

	// Parse image reference: [registry[:port]/][namespace/]repository[:tag]
	// The tricky part is distinguishing between:
	// - localhost:5000/myimage:v1 (registry with port)
	// - node:18 (repository with tag)
	// Key insight: if there's a "/" after the first ":", it's a registry with port

	parts := strings.Split(imageWithTag, "/")

	if len(parts) == 1 {
		// Simple case: repository[:tag] like "node:18"
		result.Repository, result.Tag = splitRepositoryTag(parts[0])
		return result
	}

	// Check if first part looks like a registry (contains "." or ":" or is "localhost")
	firstPart := parts[0]
	if isRegistryWithOptionalPort(firstPart) {
		result.Registry = firstPart
		if len(parts) == 2 {
			// registry/repository[:tag]
			result.Repository, result.Tag = splitRepositoryTag(parts[1])
		} else {
			// registry/namespace[/more]/repository[:tag]
			result.Namespace = strings.Join(parts[1:len(parts)-1], "/")
			result.Repository, result.Tag = splitRepositoryTag(parts[len(parts)-1])
		}
	} else {
		// No registry, just namespace/repository[:tag]
		result.Namespace = strings.Join(parts[:len(parts)-1], "/")
		result.Repository, result.Tag = splitRepositoryTag(parts[len(parts)-1])
	}

	return result
}

// splitRepositoryTag splits "repository:tag" into repository and tag.
// Returns (repository, tag) where tag may be empty.
func splitRepositoryTag(s string) (string, string) {
	idx := strings.LastIndex(s, ":")
	if idx == -1 {
		return s, ""
	}
	return s[:idx], s[idx+1:]
}

// isRegistryWithOptionalPort checks if a string looks like a registry hostname,
// possibly with a port number (e.g., "ghcr.io", "localhost:5000", "localhost").
func isRegistryWithOptionalPort(s string) bool {
	// Check if it contains a dot (domain name)
	if strings.Contains(s, ".") {
		return true
	}
	// Check if it's localhost (with or without port)
	if s == "localhost" || strings.HasPrefix(s, "localhost:") {
		return true
	}
	// Check if it's a host with port number (e.g., "myregistry:5000")
	// A port number is typically just digits after a colon
	if idx := strings.Index(s, ":"); idx != -1 {
		port := s[idx+1:]
		if isNumeric(port) {
			return true
		}
	}
	return false
}

// isNumeric checks if a string consists only of digits.
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

// IsPinned returns true if the image is pinned by SHA256 digest.
func (d *DockerImageRef) IsPinned() bool {
	return d.Digest != ""
}

// IsLatestTag returns true if the image uses the "latest" tag or no tag (implicit latest).
func (d *DockerImageRef) IsLatestTag() bool {
	return d.Tag == "latest" || (d.Tag == "" && d.Digest == "")
}

// HasTag returns true if the image has an explicit tag.
func (d *DockerImageRef) HasTag() bool {
	return d.Tag != ""
}

// ImagePinStatus represents the pin status of a Docker image.
type ImagePinStatus int

const (
	// ImagePinStatusPinned indicates the image is pinned by SHA256 digest.
	ImagePinStatusPinned ImagePinStatus = iota
	// ImagePinStatusLatest indicates the image uses "latest" tag or no tag.
	ImagePinStatusLatest
	// ImagePinStatusTagOnly indicates the image uses a specific tag but no digest.
	ImagePinStatusTagOnly
	// ImagePinStatusUnpinned indicates the image has no tag and no digest.
	ImagePinStatusUnpinned
	// ImagePinStatusExpression indicates the image is specified by an expression.
	ImagePinStatusExpression
)

// GetPinStatus returns the pin status of the Docker image.
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
	if d.HasTag() {
		return ImagePinStatusTagOnly
	}
	return ImagePinStatusUnpinned
}

// UnpinnedImagesRule checks if container images in jobs are pinned by SHA256 digest.
type UnpinnedImagesRule struct {
	BaseRule
}

// NewUnpinnedImagesRule creates a new UnpinnedImagesRule.
func NewUnpinnedImagesRule() *UnpinnedImagesRule {
	return &UnpinnedImagesRule{
		BaseRule: BaseRule{
			RuleName: "unpinned-images",
			RuleDesc: "Warn if container images are not pinned by SHA256 digest.",
		},
	}
}

// VisitJobPre checks container and service images in each job.
func (rule *UnpinnedImagesRule) VisitJobPre(node *ast.Job) error {
	// Check job container image
	if node.Container != nil && node.Container.Image != nil {
		rule.checkImage(node.Container.Image, "container", node.ID)
	}

	// Check service images
	for serviceName, service := range node.Services {
		if service.Container != nil && service.Container.Image != nil {
			rule.checkImage(service.Container.Image, "service "+serviceName, node.ID)
		}
	}

	return nil
}

// checkImage validates a Docker image reference.
func (rule *UnpinnedImagesRule) checkImage(image *ast.String, context string, jobID *ast.String) {
	if image == nil || image.Value == "" {
		return
	}

	ref := ParseDockerImageRef(image.Value)
	status := ref.GetPinStatus()

	switch status {
	case ImagePinStatusPinned:
		// Image is pinned by SHA256 digest - no warning
		return

	case ImagePinStatusLatest:
		// Latest tag or no tag - high severity
		rule.Errorf(image.Pos,
			"container image '%s' in %s of job '%s' is using 'latest' tag or no tag, which is mutable and poses a supply chain risk. Pin the image using SHA256 digest (e.g., image:tag@sha256:...).",
			image.Value, context, jobID.Value)

	case ImagePinStatusTagOnly:
		// Specific tag but no digest - medium severity
		rule.Errorf(image.Pos,
			"container image '%s' in %s of job '%s' is using a tag without SHA256 digest. Tags are mutable and can be overwritten. Consider pinning with SHA256 digest (e.g., %s@sha256:...).",
			image.Value, context, jobID.Value, image.Value)

	case ImagePinStatusUnpinned:
		// No tag and no digest - high severity
		rule.Errorf(image.Pos,
			"container image '%s' in %s of job '%s' has no tag or digest specified. This defaults to 'latest' and poses a supply chain risk. Pin the image using SHA256 digest.",
			image.Value, context, jobID.Value)

	case ImagePinStatusExpression:
		// Expression - check if we can analyze it
		rule.checkExpressionImage(image, context, jobID)
	}
}

// checkExpressionImage handles images specified by expressions.
func (rule *UnpinnedImagesRule) checkExpressionImage(image *ast.String, context string, jobID *ast.String) {
	expr := image.Value

	// Check if it's a matrix variable
	if strings.Contains(expr, "matrix.") {
		rule.Errorf(image.Pos,
			"container image '%s' in %s of job '%s' is specified using a matrix variable. Ensure all matrix values are pinned by SHA256 digest for supply chain security.",
			expr, context, jobID.Value)
		return
	}

	// General expression warning
	rule.Errorf(image.Pos,
		"container image '%s' in %s of job '%s' is specified using an expression. Unable to verify if the image is pinned by SHA256 digest. Consider using a literal image reference with SHA256 digest for supply chain security.",
		expr, context, jobID.Value)
}
