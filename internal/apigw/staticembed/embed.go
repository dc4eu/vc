package staticembed

import "embed"

//go:embed index.html consent.js bulma.min.css
var FS embed.FS
