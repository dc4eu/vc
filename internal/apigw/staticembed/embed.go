package staticembed

import "embed"

//go:embed index.html consent.js consent.css bulma.min.css person-identification-data-svg-example-01.svg
var FS embed.FS
