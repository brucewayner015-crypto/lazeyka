//go:build !unix

package svyazka

func chownLikeDir(path, dir string) {}
