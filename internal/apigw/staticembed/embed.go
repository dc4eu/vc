package staticembed

import "embed"

//go:embed index.html consent.js consent.css bulma.min.css
var FS embed.FS
