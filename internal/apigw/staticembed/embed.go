package staticembed

import "embed"

//go:embed consent.html consent.js consent.css bulma.min.css
var FS embed.FS
