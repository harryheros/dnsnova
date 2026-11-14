//go:build !linux

package server

func reportedToUsable(n int) int { return n }
