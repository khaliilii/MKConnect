// Package version holds build information shared by the CLI and the desktop app.
package version

// Version is set at build time with
// -ldflags "-X github.com/khaliilii/MKConnect/internal/version.Version=v1.2.3".
var Version = "dev"

const (
	// Author is the developer's GitHub handle.
	Author = "khaliilii"
	// AuthorURL is the developer's GitHub profile.
	AuthorURL = "https://github.com/khaliilii"
	// ProjectURL is the source repository.
	ProjectURL = "https://github.com/khaliilii/MKConnect"
)
