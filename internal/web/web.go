package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed dist/*
var assets embed.FS

func Handler() http.Handler {
	sub, _ := fs.Sub(assets, "dist")
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, e := fs.Stat(sub, r.URL.Path[1:]); e != nil {
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/"
			files.ServeHTTP(w, r2)
			return
		}
		files.ServeHTTP(w, r)
	})
}
